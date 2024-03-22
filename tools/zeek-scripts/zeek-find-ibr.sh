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

# Extract IBR-like "connections" from zeek logs

SCRIPTDIR=$(dirname $(readlink -f $0))

if [ -z "$1" ]; then
    echo "ERROR: no parameter file given"
    exit 1
fi

. "$1"
if [ $? -ne 0 ]; then
    echo "ERROR: could not open param file [$1]"
    exit 1
fi

if [ -z "$ZEEK_DATANAME" ]; then
    echo "ERROR: no ZEEK_DATANAME specified"
    exit 1
fi

if [ -z "$ZEEK_LOGDIR" ]; then
    echo "ERROR: no ZEEK_LOGDIR specified"
    exit 1
fi

if [ -z "$ZEEK_CSVDIR" ]; then
    echo "ERROR: no ZEEK_CSVDIR specified"
    exit 1
fi

if [ -z "$ZEEK_SUBNETS" ]; then
    echo "ERROR: no ZEEK_SUBNETS specified"
    exit 1
fi

if [ -z "$ZEEK_DATE_REGEX" ]; then
    echo "ERROR: no ZEEK_DATE_REGEX specified"
    exit 1
fi

if [ -z "$CONCUR" ]; then
    CONCUR=1
fi
if [ $CONCUR -lt 1 ]; then
    CONCUR=1
fi

summarize_ibr() {
    local logdir="$1"
    local outdir="$2"
    local subnets="$3"
    local date_regex="$4"
    local concur="$5"

    mkdir -p "$outdir"

    local cnt=0
    local dir
    local fname

    for dir in $logdir/$date_regex/ ; do
	for fname in $dir/conn.[012]*log.gz; do
	    if [ ! -f "$fname" ]; then
		# echo "skipping $fname"
		continue
	    fi

	    local hname=$(echo $fname | sed -e 's/.*\///' -e 's/:.*$//')
	    local hour=$(echo $hname | sed -e 's/conn.//')
	    local day=$(basename $dir)

	    local out="$outdir/$ZEEK_DATANAME-$day-$hour.csv.gz"
	    if [ ! -f "$out" ]; then
		echo date $day $hour
		zcat "$fname" \
			| "$SCRIPTDIR"/zeek2csv $subnets \
			| gzip -c \
			> "$out" &

		cnt=$((cnt + 1))
		if [ $cnt -ge $CONCUR ]; then
		    wait -n
		fi
	    fi
	done

	for fname in $dir/conn.[012]*log; do
	    if [ ! -f "$fname" ]; then
		# echo "skipping $fname"
		continue
	    fi

	    local hname=$(echo $fname | sed -e 's/.*\///' -e 's/:.*$//')
	    local hour=$(echo $hname | sed -e 's/conn.//')
	    local day=$(basename $dir)

	    local out="$outdir/$ZEEK_DATANAME-$day-$hour.csv.gz"
	    if [ ! -f "$out" ]; then
		echo date $day $hour
		cat "$fname" \
			| "$SCRIPTDIR"/zeek2csv $subnets \
			| gzip -c \
			> "$out" &

		cnt=$((cnt + 1))
		if [ $cnt -ge $concur ]; then
		    wait -n
		fi
	    fi
	done
    done
    wait

    chmod 444 "$outdir"/*.csv.gz
}

summarize_ibr "$ZEEK_LOGDIR" "$ZEEK_CSVDIR" \
	"$ZEEK_SUBNETS" "$ZEEK_DATE_REGEX" "$CONCUR"
