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

# Instructions:
#
# This script takes a single optional commandline parameter,
# which is a file defining the parameters listed below,
# in bash syntax.
#
# These variables can also be passed in via commandline
# variables, i.e.
#
# PCAPDIR=/some/path CSV3DIR=/another/path ./fast-make-csv.sh
#
# If a file is specified, it overrides the values
# passed on the commandline.
#
# All of these variables must be defined, except for CONCUR,
# which has a default value of 4.  This is adequate for low-end
# machines, but fast machines with more than eight cores can
# run with a higher concurrency.

# PCAPDIR is the path to the directory containing the pcap.gz files.
# Note that this script assumes that all pcap files are stored in
# gzipped form (to save space).
#
# CSV3DIR is the name of the directory where the csv outfile files
# should be created.  This directory (and its ancestors) will be
# created, if needed.
#
# CONCUR is the number of concurrent processes to run.

SCRIPTDIR=$(dirname $(readlink -f "$0"))
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

if [ -z ${PCAPDIR+x} ]; then
    echo "ERROR: $PNAME: required variable PCAPDIR is not set"
    exit 1
elif [ ! -d "${PCAPDIR}" ]; then
    echo "ERROR: $PNAME: PCAPDIR $PCAPDIR does not exist"
    exit 1
fi

if [ -z ${CSV3DIR+x} ]; then
    echo "ERROR: $PNAME: required variable CSV3DIR is not set"
    exit 1
elif [ ! -d "${CSV3DIR}" ]; then
    mkdir -p "${CSV3DIR}"
    if [ ! -d "${CSV3DIR}" ]; then
	echo "ERROR: $PNAME: could not create CSV3DIR [$CSV3DIR]"
	exit 1
    fi
fi

if [ -z ${DATANAME+x} ]; then
    echo "ERROR: $PNAME: required variable DATANAME is not set"
    exit 1
fi

export DATANAME

if [ -z ${CONCUR+x} ]; then
    CONCUR=4
fi

PCAP2CSV="$SCRIPTDIR/../../bin/cpcap2csv"
PCAPWORKER="$SCRIPTDIR/HELPERS/csv-worker.sh"
FILTERCSV="$SCRIPTDIR/HELPERS/csv-valid-subnets"

if [ ! -x "$PCAP2CSV" ]; then
    echo "ERROR: $PNAME: cannot execute PCAP2CSV [$PCAP2CSV]"
    exit 1
fi

if [ ! -x "$FILTERCSV" ]; then
    echo "ERROR: $PNAME: cannot execute FILTERCSV [$FILTERCSV]"
    exit 1
fi


find_missing() {

    "$SCRIPTDIR/HELPERS/find-missing.py" \
		"$PCAPDIR" .pcap.gz "$CSV3DIR" .csv.gz
}

# Process any pcap files that don't already have a matching csv
# file
#
fill_missing() {

    local cnt=0
    local missing=$(find_missing)
    local name

    # If there are no missing files, then we can
    # exit right away
    #
    if [ -z "$missing" ]; then
	exit 0
    fi

    for name in $missing; do
	echo "    " converting pcap to csv for $name

	"$PCAPWORKER" \
		"${PCAPDIR}/${name}.pcap.gz" \
		"${CSV3DIR}/${name}.csv.gz" \
		"-1" "$PCAP2CSV" "$FILTERCSV" &

	cnt=$((cnt + 1))
	if [ $cnt -ge $CONCUR ]; then
	    wait -n
	    if [ $? -ne 0 ]; then
		echo "$PNAME: subprocess failed $?"
		exit 1
	    fi
	fi
    done

    wait
}

fill_missing

# make the new files read-only
(cd "$CSV3DIR"; chmod 444 *.csv.gz)

exit 0
