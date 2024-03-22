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

if [ -z ${MEANIEDIR+x} ]; then
    echo "ERROR: $PNAME: required variable MEANIEDIR is not set"
    exit 1
fi
if [ ! -d "${MEANIEDIR}" ]; then
    echo "ERROR: $NAME: MEANIEDIR [$MEANIEDIR] does not exist"
    exit 1
fi


TEXTDIR="$MEANIEDIR/text"
OUTDIR="$MEANIEDIR/hour2src"
CUMMCNTDIR="$MEANIEDIR/cumcnt-7"

MERGER="$SCRIPTDIR"/merger.py

CONCUR=4

count_sources() {

    mkdir -p "$OUTDIR"

    local cnt=0

    local tname
    for tname in "$TEXTDIR"/*.txt; do
	local oname="$OUTDIR"/${tname##*/"$DATANAME"-}
	oname=${oname%%.txt}.cnt

	if [ ! -f "$oname" ]; then
	    if [ -s "$tname" ]; then
		echo Counting sources for $oname
		cat $tname | awk -F, '{print $1}' | sort | uniq -c \
			> "$oname" &
		cnt=$((cnt + 1))
		if [ $cnt -ge $CONCUR ]; then
		    wait -n
		fi
	    else
		touch "$oname"
	    fi
	fi
    done

    wait

    (cd "$OUTDIR"; chmod 444 *.cnt)
}

total_saddrs_seen() {

    local src_set="$1"
    local num_unique="$2"
    local tmpfile="$src_set".tmp

    shift; shift

    rm -f "$num_unique"
    rm -f "$src_set" "$src_set"_
    touch "$src_set"

    local cnt=0

    for tname in $*; do
	echo $tname
	cat $tname | awk '{print $2}' | sort -u > "$tmpfile"
	sort -m -u "$tmpfile" "$src_set" > "$src_set"_
	mv "$src_set"_ "$src_set"
	echo $cnt $(basename -s .cnt $tname) $(cat "$src_set" | wc -l) \
		>> "$num_unique"
	cnt=$((cnt + 1))
    done

    rm -f "$tmpfile" "$src_set"
}

total_cnt_by_saddr() {

    local src_set="$1"
    local num_unique="$2"
    local tmpfile="$num_unique".tmp

    shift; shift;

    rm -f "$src_set"
    touch "$src_set"

    rm -f "$tmpfile"
    touch "$tmpfile"

    rm -f "$num_unique"

    mkdir -p "$(dirname $src_set)"
    mkdir -p "$(dirname $num_unique)"

    local cnt=0

    for tname in $*; do

	local name=$(basename -s .cnt $tname)

	cat "$tname" "$tmpfile" \
		| pypy3 "$MERGER" \
		| sort -nr > "$tmpfile"_

	cp "$tmpfile"_ "$src_set"
	mv "$tmpfile"_ "$tmpfile"

	echo $cnt $name $(cat "$src_set" | wc -l) \
		>> "$num_unique"
	cnt=$((cnt + 1))
    done
    
    rm -f "$src_set" "$tmpfile" "$tmpfile"_
}

count_sources
# total_saddrs_seen \
#	$DATADIR/top_ports $DATADIR/num_unique.txt $DATADIR/hour2src/*.cnt

exit 

