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

# Script to "fix" CSV files so that they align on hour boundaries.
# The CSV files that are created directly from pcap files (using
# fast-make-csv.sh or make-csv.sh) have the same packets as their
# source pcap files, and the pcap files often begin/end on non-hour
# boundaries (usually off by a few seconds) or might have a few
# packets that end up in the wrong file.  This script fixes that
# by searching through time-adjacent CSV files to find any rows
# that should be in a given file, and omit any rows that should
# not.  The actual work is done using date-scrubber.sh (which is
# run as a separate process so we can have several of them running
# concurrently).

# Instructions:
#
# This script takes a single optional commandline parameter,
# which is a file defining the parameters listed below,
# in bash syntax.
#
# These variables can also be passed in via commandline
# variables, i.e.
# CSV3DIR=foo FCSVDIR=bar FIXEDDIR=qux ./refix-hours.sh
#
# PARAMETERS:
#
# CSV3DIR - the path to the directory containing the input CSV files
#
# FCSVDIR - the path to the directory containing the "fixed" CSV
# files that have already been computed.  If this script is
# successful then this directory will be modified by this script
# (to contain the output of a successful run).  DO NOT set FIXEDDIR
# to the same path.
#
# FIXEDDIR - the path to the directory for the output CSV files.
# This directory will be created if it does not exist.  DO NOT USE
# THE SAME DIRECTORY AND OVERWRITE THE INPUT -- this will fail and
# can leave the data corrupted!
#
# TIMEZONE - the timezone code for the timezone where the data
# collection took place.  This is needed to map the filenames
# to the time since the start of the epoch of each file.  If
# TIMEZONE is not specified, the local timezone for the host
# is used.
#
# CONCUR - the number of concurrent processes to run.  This depends
# on the number of cores you have and the I/O bandwidth of the system;
# for a typical machine it can be 2-4.  For proxy0, 6 is OK.
# If this is too high, the file system will thrash and everything will
# run slower.

SCRIPTDIR=$(dirname $(readlink -f "$0"))
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

if [ -z ${CSV3DIR+x} ]; then
    echo "ERROR: $PNAME: required variable CSV3DIR is not set"
    exit 1
elif [ ! -d "${CSV3DIR}" ]; then
    mkdir -p "$CSV3DIR"
    if [ -d "$CSV3DIR" ]; then
	echo "INFO: $PNAME: created CSV3DIR [$CSV3DIR]"
    else
	echo "ERROR: $PNAME: could not create CSV3DIR [$CSV3DIR]"
	exit 1
    fi
fi

if [ -z ${FCSVDIR+x} ]; then
    echo "ERROR: $PNAME: required variable FCSVDIR is not set"
    exit 1
elif [ ! -d "${FCSVDIR}" ]; then
    mkdir -p "$FCSVDIR"
    if [ -d "$FCSVDIR" ]; then
	echo "INFO: $PNAME: created FCSVDIR [$FCSVDIR]"
    else
	echo "ERROR: $PNAME: could not create FCSVDIR [$FCSVDIR]"
	exit 1
    fi
fi

if [ -z ${FIXEDDIR+x} ]; then
    echo "ERROR: $PNAME: required variable FIXEDDIR is not set"
    exit 1
elif [ ! -d "${FIXEDDIR}" ]; then
    mkdir -p "${FIXEDDIR}"
    if [ -d "${FIXEDDIR}" ]; then
	echo "INFO: $PNAME: created FIXEDDIR [$FIXEDDIR]"
    else
	echo "ERROR: $PNAME: could not create FIXEDDIR [$FIXEDDIR]"
	exit 1
    fi
fi

if [ -z ${TIMEZONE+x} ]; then
    TIMEZONE=""
fi

if [ -z ${CONCUR+x} ]; then
    CONCUR=4
fi

# If FIXDDIR and FCSVDIR are the same, then fixing the start/end
# time of the CSV files is not necessary (or at least not requested),
# so we can skip over this step entirely and exit immediately.
#
if [ $(readlink -f "$CSV3DIR") = $(readlink -f "$FCSVDIR") ]; then
    echo "$PNAME: input and output directories are the same, so therefore"
    echo "        assuming time offsets DO NOT need to be fixed"
    exit 0
fi

if [ $(readlink -f "$CSV3DIR") = $(readlink -f "$FIXEDDIR") ]; then
    echo "$PNAME: ERROR: input and scratch directories are the same"
    exit 1
fi

find_missing() {
    local csv3dir="$1"
    local fcsvdir="$2"

    local missing=$("$SCRIPTDIR/HELPERS/find-missing.py" \
	    "$csv3dir" .csv.gz "$fcsvdir" .csv.gz)

    # It's possible that the previous run left a partially
    # complete file at the end of any gaps (such as the
    # last file).  We might need to re-do any such file,
    # so for each missing file, see whether it's immediately
    # before or after a file that's already in FCSVDIR,
    # and if so, add the name of that file in FCSVDIR to
    # the list of missing files so we'll process it again.

    local added=""
    (cd "$fcsvdir"; ls | grep .csv.gz$ ) > /tmp/listing-fcsv-$$
    (cd "$csv3dir"; ls | grep .csv.gz$ ) > /tmp/listing-csv-$$

    local name

    for name in $missing; do
	local before=$(grep -B1 $name.csv.gz /tmp/listing-csv-$$ | head -1)
	if [ ! -z "$before" ]; then
	    grep $before /tmp/listing-fcsv-$$ > /dev/null
	    if [ $? -eq 0 ]; then
		#echo "adding $before"
		local new=$(echo $before | sed -e 's/.csv.gz$//')
		added="$added $new"
	    fi
	fi

	local after=$(grep -A1 $name.csv.gz /tmp/listing-csv-$$ | tail -1)
	if [ ! -z "$after" ]; then
	    grep $after /tmp/listing-fcsv-$$ > /dev/null
	    if [ $? -eq 0 ]; then
		#echo "adding $after"
		local new=$(echo $after | sed -e 's/.csv.gz$//')
		added="$added $new"
	    fi
	fi
    done

    rm -f /tmp/listing-fcsv-$$ /tmp/listing-csv-$$

    echo $missing $added
}

run_fixer() {
    local csv3dir="$1"
    local outdir="$2"
    local fcsvdir="$3"
    local concur="$4"

    local fname
    local missing=$(find_missing "$csv3dir" "$fcsvdir")

    local cnt=0
    for fname in $missing ; do
	echo "    " fixing time in csv file $fname
	bash $SCRIPTDIR/HELPERS/date-scrubber.sh \
		"$fname" "$csv3dir" "$outdir" "$DATANAME" "$TIMEZONE" &

	cnt=$((cnt + 1))
	if [ $cnt -ge $concur ]; then
	    wait -n
	    if [ $? -ne 0 ]; then
		echo "ERROR: $PNAME: date-scrubber subprocess failed $?"
		exit 1
	    fi
	fi
    done
    wait
}

# After we've calculated the "fixed" hours, move the missing
# hours to the fcsvdir.  Then check any files that are both
# in the fixeddir and fcsvdir -- they *should* be identical,
# if the current assumptions hold about how the input files
# line up.  If they're not identical, then flag the possible
# error (so the operator can figure out what happened, with
# any luck), but if they are identical then remove them
# because they are no longer needed.
# 
move_output() {
    local fixeddir="$1"
    local fcsvdir="$2"

    local missing=$("$SCRIPTDIR/HELPERS/find-missing.py" \
	    "$fixeddir" .csv.gz "$fcsvdir" .csv.gz)

    local fname

    for fname in $missing; do
	# echo $fname
	mv "$fixeddir/$fname".csv.gz "$fcsvdir/$fname".csv.gz
	if [ $? -ne 0 ]; then
	    echo "ERROR: $PNAME: moving $fname to $fcsvdir FAILED"
	    exit 1
	fi

	# We want the new files to be read-only when we're done
	#
	chmod 444 "$fcsvdir/$fname.csv.gz"
    done

    for fname in $(ls "$fixeddir/" | grep csv.gz$); do
	echo "    " checking overlapping file $fname
	cmp "$fixeddir/$fname" "$fcsvdir/$fname"
	if [ $? -ne 0 ]; then
	    echo "    " WARNING: $PNAME: $fname does not match
	    exit 1
	else
	    rm -f "$fixeddir/$fname"
	fi
    done
}

echo "$PNAME: Fixing hours"
run_fixer "$CSV3DIR" "$FIXEDDIR" "$FCSVDIR" $CONCUR
echo "$PNAME: Moving output"
move_output "$FIXEDDIR" "$FCSVDIR"

# Note: we don't remove the FIXEDDIR, because it's possible that
# the operator left other stuff in it.  We just leave it be.
# If everything went well, it will be empty.

exit 0
