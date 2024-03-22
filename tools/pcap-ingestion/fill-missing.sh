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

if [ -z ${FCSVDIR+x} ]; then
    echo "ERROR: $PNAME: required variable FCSVDIR is not set"
    exit 1
elif [ ! -d "${FCSVDIR}" ]; then
    echo "ERROR: $PNAME: FCSVDIR $FCSVDIR does exist"
    exit 1
fi

# If any hours are missing from the $FCSVDIR directory (which can
# happen if there are missing pcap files, due to connectivity problems,
# or hardware failures, or human error), then fill them in with
# empty hours.
#
# It is useful to have empty files (instead of absent files) because
# some other utilities assume that there are fixed number of hours in
# the day, and that each file represents a constant offset from the
# previous, etc.
#
# TODO: this checks the entire directory every time (not just new files)
# and therefore takes more time than it really should.
#
fill_csvin_by_date() {
    local basedir="$1"

    local firstname=$(basename $(cd "$basedir/"; ls | grep .csv.gz$ | head -1))
    local lastname=$(basename $(cd "$basedir/"; ls | grep .csv.gz$ | tail -1))
    #echo first $firstname last $lastname

    # Convert the filename into a valid date string
    #
    local firstdate=$(echo $firstname \
	    | sed -e "s/$DATANAME-//" -e 's/.csv.gz$/:00/' -e 's/\(.*\)-/\1 /')
    local lastdate=$(echo $lastname \
	    | sed -e "s/$DATANAME-//" -e 's/.csv.gz$/:00/' -e 's/\(.*\)-/\1 /')
    # echo first $firstdate last $lastdate

    # Convert the date strings into seconds since the epoch
    #
    local firstsec=$(date --date="$firstdate" +%s)
    local lastsec=$(date --date="$lastdate" +%s)
    # echo first $firstsec last $lastsec

    local start=$firstsec
    while [ $start -le $lastsec ]; do

	local name=$(date --date="@$start" +"$DATANAME-%Y-%m-%d-%H.csv.gz")
	local fname="$basedir/$name"
	if [ ! -f "$basedir/$name" ]; then
	    echo "    Adding missing $name"
	    touch "${fname%.gz}"
	    gzip "${fname%.gz}"
	fi

	start=$((start + 3600))
    done

    (cd "$basedir"; chmod 444 *.gz)
}

fill_csvin_by_date "$FCSVDIR"

exit 0
