#!/usr/bin/env bash

# CODEMARK: nice-ibr
#
# Copyright (C) 2020-2024 - Raytheon BBN Technologies Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
#
# You may obtain a copy of the License at
# http://www.apache.org/licenses/LICENSE-2.0.
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the License.
#
# Distribution Statement "A" (Approved for Public Release,
# Distribution Unlimited).
#
# This material is based upon work supported by the Defense
# Advanced Research Projects Agency (DARPA) under Contract No.
# HR001119C0102.  The opinions, findings, and conclusions stated
# herein are those of the authors and do not necessarily reflect
# those of DARPA.
#
# In the event permission is required, DARPA is authorized to
# reproduce the copyrighted material for use as an exhibit or
# handout at DARPA-sponsored events and/or to post the material
# on the DARPA website.
#
# CODEMARK: end

# Required parameters:
#
# DATANAME - the name of the telescope
#
# FCSVDIR - Where to get the CSV files
#
# SUBNETS: a list all of the subnets that you want to check
# for horizontal scans.  For this script, these are assumed
# to be /24 subnets or smaller.
#
# DATEEXPR - A date pattern for the input files.  For example,
# an expression of "2023-10-01" will match all the input files
# from October 1st, 2023.
#
# CONCUR - the maximum number of jobs to launch concurrently.
# Most machines will happily run at least two concurrent instances
# of find-fast-runs, and some will will run many.  The storage
# bandwidth is usually exhausted before all the cores are busy...
# For my current machine, 4 is a reasonably compromise.
#
# PYTHON3 - the python3-compatible interpreter to use.  If you
# have pypy3, use that; otherwise use python3

SCRIPTDIR=$(readlink -f $(dirname "$0"))
PNAME=$(basename "$0")

if [ $# -gt 1 ]; then
    echo "ERROR: $PNAME: usage: $0 [param-file]"
    exit 1
fi

if [ $# -eq 1 ]; then
    if [ ! -r "$1" ]; then
	echo "ERROR: $PNAME: cannot read parameter file [$1]"
	exit 1
    fi

    . "$1"
    if [ $? -ne 0 ]; then
	echo "ERROR: $PNAME: bad parameter file [$1]"
	exit 1
    fi
fi

if [ -z ${DATANAME+x} ]; then
    echo "ERROR: $PNAME: required variable DATANAME is not set"
    exit 1
fi

if [ -z ${FCSVDIR+x} ]; then
    echo "ERROR: $PNAME: required variable FCSVDIR is not set"
    exit 1
fi

if [ -z ${SUBNETS+x} ]; then
    echo "ERROR: $PNAME: required variable SUBNETS is not set"
    exit 1
fi

if [ -z ${DATEEXPR+x} ]; then
    echo "ERROR: $PNAME: required variable DATEEXPR is not set"
    exit 1
fi

# Optional local parameters:
#
# MAXTIMES: a list of the maximum number of seconds that
# a scan can last.  This is a list, instead of a single number,
# because it can be useful to compute this for different lengths
# of time (i.e. short scans of less than 10s and medium-length
# scans of less than 600s).  Some scans can take several hours
# (or even multiple days), but the memory required to track
# very long scans that might never complete can be enormous,
# so you usually don't want to set this too large.
#
# SIZES: a list of sizes, in bits, of the prefix length of
# each subnet scan.  For example, 24 looks for /24 scans
# (across a 256-address subnet), while 26 looks for /26
# scans (each with 64 elements).  Note that not all combos
# of SUBNET and SIZES make sense: it is necessary for a
# SUBNET to be aligned on a SIZE boundary.  For example,
# If subnet base is 1.2.3.0, then the size has to be 24
# or larger because the 24th bit of 1.2.3.0 is 1, so
# the smallest possible subnet mask is 24 bits.

if [ -z ${CONCUR+x} ]; then
    CONCUR=4
fi

if [ -z ${MAXTIMES+x} ]; then
    MAXTIMES="10 600"
fi

if [ -z ${SIZES+x} ]; then
    SIZES="24"
fi

OUTDIR=./"$DATANAME"-output

PYTHON3=python3
FILTERIP="$SCRIPTDIR/../../bin/filter-ip"

run_for_size() {
    local preflen="$1"
    local maxtime="$2"
    local suff_size="$3"

    mkdir -p "$OUTDIR/out-$preflen-$maxtime"

    cnt=1
    for subnet in $SUBNETS; do
	out="$OUTDIR"/out-"$preflen-$maxtime"/"$subnet".txt.gz
	if [ ! -f "$out" ]; then
	    echo starting $out at $(date)

	    # NOTE: Filtering out the source 1889359688 is useful
	    # because this source has had a pathological behavior that
	    # sends ENORMOUS numbers of duplicate packets -- but none of
	    # them appear to be part of any run we've seen (at least SO
	    # FAR).
	    #
	    # NOTE: Filtering out the source 3236589320 is helpful
	    # because this source sends a lot of ICMP probes that NEVER
	    # turn into runs (so far), but cycle around in a pattern that
	    # make them difficult to filter out and gums up the
	    # run-finding heuristics.

	    zcat "$FCSVDIR"/"$DATANAME"-"$DATEEXPR"*.csv.gz \
		    | "$FILTERIP" -r -n2 -r -s $subnet/$preflen \
		    | grep -v '^1889359688,' \
		    | grep -v '^3236589320,' \
		    | "$PYTHON3" "$SCRIPTDIR"/find-fast-runs \
			    -p "$preflen" -m "$maxtime" -s "$suff_size" \
		    | gzip -c \
		    > "$out" &
	    cnt=$((cnt + 1))
	    if [ $cnt -gt "$CONCUR" ]; then
		wait -n
	    fi
	fi
    done
    wait
}

mkdir "$OUTDIR"

for maxtime in $MAXTIMES; do
    for size in $SIZES; do
	run_for_size "$size" "$maxtime" 0 1
    done
done
