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

# For each CSV file in $FCSVDIR, find all the subnets present
# during the corresponding hour.  Finds the /24, /20, and /16
# subnets, and prints them, one per line, in a corresponding
# file in $SUBNETDIR. 


SCRIPTDIR=$(readlink -f $(dirname "$0"))
PNAME=$(basename "$0")

if [ $# -gt 1 ]; then
    echo "ERROR: $PNAME usage: $0 [param-file]"
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

if [ -z ${SUBNETDIR+x} ]; then
    echo "ERROR: $PNAME: required variable SUBNETDIR is not set"
    exit 1
fi
mkdir -p "${SUBNETDIR}"
if [ ! -d "${SUBNETDIR}" ]; then
    echo "ERROR: $PNAME: SUBNETDIR $SUBNETDIR does not exist/cannot be created"
    exit 1
fi

if [ -z ${FCSVDIR+x} ]; then
    echo "ERROR: $PNAME: required variable FCSVDIR is not set"
    exit 1
fi
if [ ! -d "${FCSVDIR}" ]; then
    echo "ERROR: $PNAME: FCSVDIR $FCSVDIR does not exist"
    exit 1
fi

CONCUR=4


find_hours() {
    (cd "$FCSVDIR" ; ls | grep .csv.gz$ \
	    | sed -e "s/$DATANAME-//" -e 's/.csv.gz//')
}


find_hourly_subnets() {

    local cnt=0
    local hour
    local iname
    local oname

    for hour in $(find_hours); do

	iname="$FCSVDIR"/$DATANAME-"$hour".csv.gz
	oname="$SUBNETDIR"/$DATANAME-"$hour".txt

	if [ ! -f "$oname" ]; then
	    echo "    Starting $hour"

	    # NOTE: if we need this to run faster, one approach is
	    # to only look at part of the input (say, the first million
	    # rows, instead of the entire file).  As long as the input
	    # isn't too small, or the number of possible subnets isn't
	    # too large, then subsampling will almost always give the
	    # correct answer.  But to keep things simple, just look
	    # at everything.
	    #
	    zcat "$iname" | "$SCRIPTDIR"/subnets.py > "$oname" &

	    cnt=$((cnt + 1))
	    if [ $cnt -ge $CONCUR ]; then
		wait -n
		if [ $? -ne 0 ]; then
		    echo "ERROR: $PNAME: subnets.py failed"
		    exit 1
		fi
	    fi
	fi
    done

    wait
}

find_hourly_subnets
