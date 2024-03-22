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


SCRIPTDIR=$(readlink -f $(dirname "$0"))
PNAME=$(basename "$0")

TCPDUMP=tcpdump

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

if [ -z ${RAWPCAPDIR+x} ]; then
    echo "ERROR: $PNAME: required variable RAWPCAPDIR is not set"
    exit 1
elif [ ! -d "${RAWPCAPDIR}" ]; then
    echo "ERROR: $PNAME: RAWPCAPDIR $RAWPCAPDIR does not exist"
    exit 1
fi

if [ -z ${PCAPDIR+x} ]; then
    echo "ERROR: $PNAME: required variable PCAPDIR is not set"
    exit 1
elif [ ! -d "${PCAPDIR}" ]; then
    mkdir -p "${PCAPDIR}"
    if [ ! -d "${PCAPDIR}" ]; then
	echo "ERROR: $PNAME: could not create PCAPDIR [$PCAPDIR]"
	exit 1
    fi
fi

if [ -z ${CONCUR+x} ]; then
    CONCUR=4
fi

if [ ! $(which "$TCPDUMP") ]; then
    echo "ERROR: $PNAME: cannot find tcpdump [$TCPDUMP]"
    exit 1
fi

find_missing() {
    local destdir="$1"
    local suff="$2"

    "$SCRIPTDIR/HELPERS/find-missing.py" \
		"$RAWPCAPDIR" .pcap.gz "$destdir" "$suff".pcap.gz
}

# Process any pcap files that haven't already been processed
#
fill_missing_main() {

    local suff=""
    local cnt=0
    local missing=$(find_missing "${PCAPDIR}" "${suff}")
    local name

    for name in $missing; do
	echo "    " prefiltering pcap $name

	gunzip -c "${RAWPCAPDIR}/${name}.pcap.gz" \
		| "$TCPDUMP" -r - -w - ip and not dst net 192.1.6.0/24 \
		| gzip -c \
		> "${PCAPDIR}/${name}${suff}.pcap.gz" &

	cnt=$((cnt + 1))
	if [ $cnt -ge $CONCUR ]; then
	    wait -n
	    if [ $? -ne 0 ]; then
		echo "ERROR: $PNAME: subprocess failed $?"
		exit 1
	    fi
	fi
    done

    wait

    (cd "${PCAPDIR}" && chmod 444 *)
}

fill_missing_192() {

    local suff="_192.1.6.0"
    local cnt=0
    local missing=$(find_missing "${PCAPDIR192}" "${suff}")
    local name

    if [ -z "$missing" ]; then
	exit 0
    fi

    # echo fill_missing_192: $missing

    for name in $missing; do
	echo "    " prefiltering $name for 192.1.6.0

	gunzip -c "${RAWPCAPDIR}/${name}.pcap.gz" \
		| "$TCPDUMP" -r - -w - ip and dst net 192.1.6.0/24 \
		| gzip -c \
		> "${PCAPDIR192}/${name}${suff}.pcap.gz" &

	cnt=$((cnt + 1))
	if [ $cnt -ge $CONCUR ]; then
	    wait -n
	    if [ $? -ne 0 ]; then
		echo "ERROR: $PNAME: subprocess failed $?"
		exit 1
	    fi
	fi
    done

    wait

    (cd "${PCAPDIR192}" && chmod 444 *)
}

# If RAWPCAPDIR and PCAPDIR are the same, then prefiltering the
# pcap files is not necessary (or at least not requested),
# so we can skip over this step entirely and exit immediately.
#
if [ $(readlink -f "$RAWPCAPDIR") = $(readlink -f "$PCAPDIR") ]; then
    echo "$PNAME: input and output pcap directories are the same, therefore"
    echo "$PNAME: assuming pcap files do not need to be prefiltered"
    exit 0
fi

echo "$PNAME: filtering main"
fill_missing_main

if [ ! -z "$PCAPDIR192" ]; then
    if [ $(readlink -f "$PCAPDIR") = $(readlink -f "$PCAPDIR192") ]; then
	echo "$PNAME: ERROR: PCAPDIR192 is the same as PCAPDIR"
	exit 1
    fi

    echo "$PNAME: filtering 192"
    fill_missing_192
fi
