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

echo "$PNAME: Prefiltering pcap files"
"$SCRIPTDIR"/prefilter-pcap.sh "$1" || exit 1

echo "$PNAME: Creating CSV files"
"$SCRIPTDIR"/fast-make-csv.sh "$1" || exit 1

echo "$PNAME: Fixing CSV files"
"$SCRIPTDIR"/refix-hours.sh "$1" || exit 1

echo "$PNAME: Filling missing hours"
"$SCRIPTDIR"/fill-missing.sh "$1" || exit 1

echo "$PNAME: Finding all subnets"
"$SCRIPTDIR"/find-subnets.sh "$1" || exit 1

echo "$PNAME: Computing trends"
"$SCRIPTDIR"/trend-by-subnet.sh "$1" || exit 1
