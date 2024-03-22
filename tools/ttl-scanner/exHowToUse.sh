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

PNAME=$(basename "$0")

# directory where scripts live
SCRIPTDIR=$(readlink -f $(dirname "$0"))

# directory where pktshow binary lives
BINDIR="$SCRIPTDIR"/../../bin

# directory where all pcaps live
PCAPDIR=.

#directory where all output files should go
OUTDIR=.

# how many jobs to run concurrently
CONCUR=6

# dates we are interested in exploring
#
# Note the expectation that files have the dates, in YYYY-MM-DD
# format, in their names somewhere
#
#DATES="2021-06-01 2021-06-02 2021-06-03 2021-06-04 2021-06-05 \
#    2021-06-06 2021-06-07 2021-06-08 2021-06-09 2021-06-10 \
#    2021-06-11 2021-06-12 2021-06-13 2021-06-14 2021-06-15 \
#    2021-06-16 2021-06-17 2021-06-18 2021-06-19 2021-06-20 \
#    2021-06-21 2021-06-22 2021-06-23 2021-06-24 2021-06-25 \
#    2021-06-26 2021-06-27 2021-06-28 2021-06-29 2021-06-30 "
DATES="2021-09-26"

process_pcaps() {

    local cnt=0
    local date
    for date in $DATES; do
	local oname="$OUTDIR/scans-$date.txt"
	if [ ! -f "$oname" ]; then
	    echo "pktshow ex-"$date".pcap.gz"
	    "$BINDIR"/pktshow "$PCAPDIR"/ex-"$date"*.pcap.gz \
		    | "$SCRIPTDIR"/find-horiz-scans -t 600 \
		    > "$oname" &
	    cnt=$((cnt + 1))
	    if [ $cnt -ge $CONCUR ]; then
		wait -n
	    fi
	fi
    done
    wait
}

create_images() {

    local cnt=0
    local iname
    for date in $DATES; do
	local oname="$OUTDIR/summ-$date.txt"
	local iname="$OUTDIR/scans-$date.txt"
	if [ ! -f "$oname" ]; then
	    echo "scan-display $iname > $oname"
	    "$SCRIPTDIR"/scan-display -q -H -I -d "$OUTDIR"/images "$iname" \
		    > "$oname" &
	    cnt=$((cnt + 1))
	    if [ $cnt -ge $CONCUR ]; then
		wait -n
	    fi
	fi
    done
    wait
}

create_sqldb() {

    echo "create-images-db"

    for date in $DATES; do
	local inames+="$OUTDIR/summ-$date.txt "
    done
    "$SCRIPTDIR"/create-images-db -p mydb -o "$OUTDIR" $inames &
    
    wait
}

if [ ! -x "$BINDIR"/pktshow ]; then
    echo "ERROR: $PNAME: pktshow is missing"
    echo "Run \"make install\" in ../C to compile and install pktshow"
    exit 1
fi

process_pcaps
create_images
create_sqldb
