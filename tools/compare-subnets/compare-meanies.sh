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
# which is a file defining the parameters it uses, in bash syntax.
#
# These variables can also be passed in via commandline
# variables, i.e.
#
# MEANIEDIR=/some/path ./compare-meanies.sh
#
# If a file is specified, the contents of the file overrides the
# values passed on the commandline.

# Required parameters:
#
# MEANIEDIR is the directory containing the output of the Meanie
# preprocessing scripts (see ../meanies for more information).
#
# DATANAME is the name of the telescope
#
# SUBNETS is the list of subnets that we are comparing
#
# DATEEXPR is a regex for the input files we want to count

SCRIPTDIR=$(readlink -f $(dirname "$0"))
PNAME=$(basename "$0")

TMPDIR="./mtmpdir"
mkdir -p "$TMPDIR"
if [ ! -d "$TMPDIR" ]; then
    echo "ERROR: $PNAME: tmpdir [$TMPDIR] does not exist"
    exit 1
fi

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

if [ -z ${SUBNETS+x} ]; then
    echo "ERROR: $PNAME: required variable SUBNETS is not set"
    exit 1
fi

if [ -z ${DATEEXPR+x} ]; then
    echo "ERROR: $PNAME: required variable DATEEXPR is not set"
    exit 1
fi

if [ -z ${MEANIEDIR+x} ]; then
    echo "ERROR: $PNAME: required variable MEANIEDIR is not set"
    exit 1
fi

FC="$SCRIPTDIR"/../../bin/firecracker
if [ ! -x "$FC" ]; then
    echo "ERROR: $PNAME: firecracker executable missing"
    exit 1
fi


# Find the count for the top 8 protocol/dport combinations
# over the input from $inputdir/$DATANAME-$DATEEXPR, for each
# all of the data, and for each individual subnets in $SUBNETS.
#
# If we're looking at meanie pcaps, there will only be one
# protocol/dport combination per day.  Even if we do more
# than eight days, we're really only interested in the TOTAL
# number, which firecracker always prints.
#
compute_counts() {
    local inputdir="$1"

    # Use a very long interval, in order to force firecracker
    # to put all of the counts into the same interval
    #
    all_seconds=$((1024 * 1024 * 4))

    local meanies=$("$FC" -T -m 1024 -I $all_seconds \
	    -t P $(echo "$inputdir/$DATANAME-$DATEEXPR"*.pcap) \
	| grep ^T \
	| awk -F, '{print $2}')
    echo "all-subnets $meanies"

    for subnet in $SUBNETS; do
	meanies=$("$FC" -T -m 1024 -I $all_seconds \
		-F D24="$subnet" -t P \
		$(echo "$inputdir/$DATANAME-$DATEEXPR"*.pcap) \
	    | grep ^T \
	    | awk -F, '{print $2}')
	echo "$subnet $meanies"
    done

    wait
}

compute_counts "$MEANIEDIR/pcap"

