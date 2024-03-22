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

SCRIPTDIR=$(readlink -f $(dirname "$0"))
PNAME=$(basename "$0")

if [ $# -ne 1 ]; then
    echo "ERROR: usage: $PNAME [param-file]"
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

# check that the parameter file contained all the
# necessary parameters

if [ -z ${DATANAME+x} ]; then
    echo "ERROR: $PNAME: required variable DATANAME is not set"
    exit 1
fi

if [ -z ${PCAPDIR+x} ]; then
    echo "ERROR: $PNAME: required variable PCAPDIR is not set"
    exit 1
fi

if [ -z ${FRAG_PCAPOUTDIR+x} ]; then
    echo "ERROR: $PNAME: required variable FRAG_PCAPOUTDIR is not set"
    exit 1
fi

if [ -z ${FRAG_CSVOUTDIR+x} ]; then
    echo "ERROR: $PNAME: required variable FRAG_CSVOUTDIR is not set"
    exit 1
fi

if [ -z ${FRAG_RESULTDIR+x} ]; then
    echo "ERROR: $PNAME: required variable FRAG_RESULTDIR is not set"
    exit 1
fi


# Because these processes are (on most systems) I/O-limited
# rather than CPU-limited, we typically want a lower level
# of concurrency than on some of the CPU-intensive tasks.
# If CONCUR isn't set, use a modest value.
#
if [ -z ${CONCUR+x} ]; then
    CONCUR=3
fi

SHOWFRAGS="$SCRIPTDIR/../../bin/show-frags"
TESTASSEM="$SCRIPTDIR/test-assembly.py"

if [ ! -x "$SHOWFRAGS" ]; then
    echo "ERROR: $PNAME: Executable $SHOWFRAGS missing?"
    exit 1
fi

if [ ! -x "$TESTASSEM" ]; then
    echo "ERROR: $PNAME: Executable $TESTASSEM missing?"
    exit 1
fi

# Scan a directory of pcap files, looking for packets
# that are IP fragments.  For each pcap file, create a
# CSV file (in $textoutdir) with a row for each fragment,
# and create a new pcap file (in $pcapoutdir) containing
# only the fragments.
#
# If BOTH of the corresponding output files for a given
# pcap file already exist, then this function will not
# do anything.  If neither or only one exists, both will
# be (re)created.
#
find_fragments() {
    local pcapdir="$1"
    local textoutdir="$2"
    local pcapoutdir="$3"

    local ifile

    mkdir -p "$textoutdir" "$pcapoutdir"
    if [ $? -ne 0 ]; then
	echo "ERROR: $PNAME: could not create output directories"
	exit 1
    fi

    # Make sure that the output pcaps do not overwrite
    # the input pcaps.
    #
    if [ $(readlink -f "$pcapdir") = $(readlink -f "$pcapoutdir") ]; then
	echo "ERROR: output would overwrite input"
	exit 1
    fi

    local cnt=0
    for ifile in "$pcapdir"/*.pcap.gz; do
	local pcap="${ifile##*/}"
	local base="${pcap%%.pcap.gz}"
	local oname="$textoutdir/$base".csv
	local pname="$pcapoutdir/$base".pcap

	if [ ! -f "$oname" ] || [ ! -f "$pname" ]; then
	    echo Starting $base
	    rm -f "$pname" "$oname"

	    # Avoid overwriting output that already exists, if any
	    #
	    if [ -f "$oname" ]; then
		oname="/dev/null"
	    elif [ -f "$pname" ]; then
		pname="/dev/null"
	    fi

	    "$SHOWFRAGS" -f -p "$pname" $ifile > "$oname" &
	    cnt=$((cnt + 1))
	    if [ $cnt -ge $CONCUR ]; then
		wait -n
	    fi
	fi
    done

    wait
}

find_hourly_counts() {
    local csvdir="$1"
    local countsfile="$2"

    rm -f "$countsfile"

    local fname
    for fname in "$csvdir"/*.csv; do

	# echo hourly count $fname
	local csv="${fname##*/}"
	local base="${csv%%.csv}"

	if [ -s "$fname" ]; then
	    local cnt=$(cat "$fname" | wc -l)
	    echo "$base $cnt" >> "$countsfile"
	else
	    echo "$base 0" >> "$countsfile"
	fi
    done
}

find_busiest_sources() {
    local csvdir="$1"
    local srcsfile="$2"
    local dstsfile="$3"

    rm -f "$srcsfile" "$dstsfile"

    local src_tmpfile="tmp-s$$.cnt"
    local dst_tmpfile="tmp-d$$.cnt"

    rm -f "$dst_tmpfile" "$src_tmpfile"

    local fname
    for fname in "$csvdir"/*.csv; do
	if [ ! -s "$fname" ]; then
	    continue
	fi

	# echo finding sources $fname
	cat "$fname" | awk -F, '{print $1}' >> "$src_tmpfile"
	cat "$fname" | awk -F, '{print $2}' >> "$dst_tmpfile"
    done

    cat "$src_tmpfile" | sort | uniq -c | sort -nr > "$srcsfile"
    cat "$dst_tmpfile" | sort | uniq -c | sort -nr > "$dstsfile"
    rm -f "$dst_tmpfile" "$src_tmpfile"
}

# Try reassembling all the fragments; see whether the pieces fit.
#
# This is not realistic because it puts *all* of the fragments
# with the same description into the same pool (potentially spanning
# months or years of time), while in reality fragments would be
# discarded if aren't reassembled within a short period of time.
#
test_reassembly() {
    local textoutdir="$1"
    local outname="$2"

    (cd "$textoutdir"; cat *.csv) \
	    | "$TESTASSEM" \
	    > "$outname"
}

# The main function: find all the fragments, and then compute
# some aggregates, and test reassembly (in a simplistic manner)
#
process_pcaps() {
    local pcapdir="$1"
    local textoutdir="$2"
    local pcapoutdir="$3"
    local name="$4"
    local resultdir="$5"

    mkdir -p "$resultdir"
    if [ $? -ne 0 ]; then
	echo "ERROR: $PNAME: could not create result directory"
	exit 1
    fi

    echo "$PNAME: Finding fragments"
    find_fragments "$pcapdir" "$textoutdir" "$pcapoutdir"

    echo "$PNAME: Finding busy hours"
    find_hourly_counts "$textoutdir" "$resultdir/$name"-hourly-counts.txt

    echo "$PNAME: Finding busy sources/destinations"
    find_busiest_sources "$textoutdir" \
	    "$resultdir/$name"-busy_srcs.txt \
	    "$resultdir/$name"-busy_dsts.txt

    echo "$PNAME: Testing reassembly"
    test_reassembly "$textoutdir" "$resultdir/$name"-reassem.csv
}

process_pcaps "$PCAPDIR" "$FRAG_CSVOUTDIR" "$FRAG_PCAPOUTDIR" \
	"$DATANAME" "$FRAG_RESULTDIR"

exit $?
