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
# FCSVDIR=foo TRENDDIR=bar ./trends-by-subnet.sh
#

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

if [ -z ${SUBNETDIR+x} ]; then
    echo "ERROR: $PNAME: required variable SUBNETDIR is not set"
    exit 1
elif [ ! -d "${SUBNETDIR}" ]; then
    echo "ERROR: $PNAME: SUBNETDIR $SUBNETDIR does not exist"
    exit 1
fi

if [ -z ${TRENDDIR+x} ]; then
    echo "ERROR: $PNAME: required variable TRENDDIR is not set"
    exit 1
elif [ ! -d "${TRENDDIR}" ]; then
    mkdir -p "${TRENDDIR}"
    if [ ! -d "${TRENDDIR}" ]; then
	echo "ERROR: $PNAME: could not create TRENDDIR [$TRENDDIR]"
	exit 1
    fi
fi

if [ -z ${CONCUR+x} ]; then
    CONCUR=4
fi

SCRATCH="./$DATANAME-scratch"
mkdir -p "$SCRATCH"

HOURLY_OUT="$TRENDDIR/all/hourly"
HOURLY_ACK_OUT="$TRENDDIR/ack/hourly"
HOURLY_NACK_OUT="$TRENDDIR/nack/hourly"
MAX=256
QUERIES="PA S24 S D"

FIRECRACKER="$SCRIPTDIR"/../../bin/firecracker
SPLITTER="$SCRIPTDIR"/HELPERS/split-by-dstnet.py

if [ ! -x "$FIRECRACKER" ]; then
    echo "ERROR: $PNAME: firecracker $FIRECRACKER not executable"
    exit 1
fi

cat_compressed() {
    local fname

    for fname in $*; do
	case "$fname" in
	    *.gz)
		gunzip -c "$fname"
		;;
	    *.lz4)
		lz4cat "$fname"
		;;
	    *)
		cat "$fname"
		;;
	esac
    done
}

get_dates() {
    (cd "$FCSVDIR"; ls \
	    | grep -E "$DATANAME"-'[0-9]{4}-[0-9]{2}-[0-9]{2}-[0-9]{2}\.csv\..*$') \
	    | sed -e 's/^.*\///' -e 's/-..\.csv.*$//' \
	    | uniq
}

make_output_directories() {

    local base="$1"
    local net
    local query

    mkdir -p "$base"

    for net in all $NETS24; do
	mkdir -p "$base/by-net/$net"
    done
}

find_missing_hours() {
    local net="$1"
    local outdir="$2"

    ("$SCRIPTDIR/HELPERS/find-missing.py" \
		"$FCSVDIR" .csv.lz4 \
		"$outdir/$net" .fc &&
	"$SCRIPTDIR/HELPERS/find-missing.py" \
		    "$FCSVDIR" .csv.gz \
		    "$outdir/$net" .fc) \
	    | uniq
}

find_all_hours() {

    (cd $FCSVDIR; ls | grep '\.csv\.gz$' | sed -e 's/.csv.gz//')
}

# Compute the subnet trends for one hour.
#
# The brute-force way of doing this is very slow for large
# telescopes, so we do something somewhat better: first we
# split the input file by destination subnet, creating multiple
# input files, one per destination network.  Then we invoke
# firecracker on each of the input files, which is generally
# very fast (for a single /24 hour).
#
# If you only have a small telescope, then this can be a
# waste of time, because the benefit of splitting the file
# doesn't save much.  For small telescopes (two or three /24s),
# it may be more efficient to do things the way that
# run_hourly_queries does, but with a D24 filter.
#
hourly_subnet_trends() {
    local hour="$1"
    local subset="$2"
    local outdir="$3"
    local filter="$4"

    echo hourly trends for $hour subset $subset by subnet
    rm -f "$SCRATCH"/*/"$hour".csv
    cat_compressed "$FCSVDIR/$hour".csv* \
	    | "$SPLITTER" "$SCRATCH" "$hour".csv 24
    if [ $? -ne 0 ]; then
	echo "ERROR: $PNAME: could not split the input"
	exit 1
    fi

    local net
    for net in $NETS24; do
	local out="$outdir/by-net/$net/$hour.fc"

	if [ ! -f "$out" ]; then

	    local in_file="$SCRATCH/$net/$hour".csv
	    if [ ! -f "$in_file" ]; then
		in_file=/dev/null
	    fi

	    # 4000 seconds is enough to ensure that we get the
	    # whole hour.  In theory 3600 is enough, but we
	    # want to make sure we don't split if there's some slop
	    # over.
	    #
	    cat "$in_file" \
		    | ${filter} \
		    | "$FIRECRACKER" -T -o "$out" \
			    -n -m "$MAX" -I 4000 ${FC_QUERY}
	fi
    done

    rm -f "$SCRATCH"/*/"$hour".csv
}


# Run all of the queries for each hour, per /24 destination
# subnet
#
run_hourly_queries_per_subnet() {
    local subset="$1"

    local hour
    local net

    local outdir
    local filter

    # Make sure that the acknowledged scanner list is built
    #
    cat /dev/null | $SCRIPTDIR/ackscan-filter.sh

    case $subset in
	all)
	    outdir="$HOURLY_OUT"
	    filter=cat
	    ;;
	ack)
	    outdir="$HOURLY_ACK_OUT"
	    filter="$SCRIPTDIR/ackscan-filter.sh -F, -r"
	    ;;
	nack)
	    outdir="$HOURLY_NACK_OUT"
	    filter="$SCRIPTDIR/ackscan-filter.sh -F,"
	    ;;
	*)
	    echo "ERROR: $PNAME: unsupported subset [$subset]"
	    exit 1
	    ;;
    esac


    local cnt=0
    for hour in $(find_all_hours); do

	local missing_net=0
	for net in $NETS24; do
	    local out="$outdir/by-net/$net/$hour.fc"

	    if [ ! -f "$out" ]; then
		missing_net=1
		break
	    fi
	done

	if [ $missing_net -ne 0 ]; then
	    (hourly_subnet_trends "$hour" "$subset" "$outdir" "$filter") &
	    cnt=$((cnt + 1))
	    if [ $cnt -ge $CONCUR ]; then
		wait -n
	    fi
	fi
    done
    wait
}

run_hourly_queries() {
    local subset="$1"

    local date
    local net

    local cnt=0

    case $subset in
	all)
	    outdir="$HOURLY_OUT"
	    filter=cat
	    ;;
	ack)
	    outdir="$HOURLY_ACK_OUT"
	    filter="$SCRIPTDIR/ackscan-filter.sh -F, -r"
	    ;;
	nack)
	    outdir="$HOURLY_NACK_OUT"
	    filter="$SCRIPTDIR/ackscan-filter.sh -F,"
	    ;;
	*)
	    echo "ERROR: $PNAME: unsupported subset [$subset]"
	    exit 1
	    ;;
    esac

    cnt=0
    for hour in $(find_all_hours); do
	local out="$outdir/by-net/all/$hour.fc"

	if [ -f "$out" ]; then
	    # echo "skipping $hour"
	    continue
	else
	    echo hourly trends for $hour subset $subset for all

	    # 4000 seconds is enough to ensure that we get the
	    # whole hour.  In theory 3600 is enough, but we
	    # want to make sure we don't split if there's some slop
	    # over.
	    #
	    (cat_compressed "$FCSVDIR/$hour".csv* \
		    | ${filter} \
		    | "$FIRECRACKER" -T -o "$out" \
			    -n -m "$MAX" -I 4000 ${FC_QUERY} \
		&& rm -f "$SCRATCH/$hour".csv) &

	    cnt=$((cnt + 1))
	    if [ $cnt -ge $CONCUR ]; then
		wait -n
	    fi
	fi

    done
    wait
}


split_by_query() {

    local base="$1"
    local date
    local net
    local query

    for query in $QUERIES; do
	for net in all $NETS24; do
	    mkdir -p "$base/$query/$net"
	done
    done

    for net in all $NETS24; do

	if [ ! -d "$base/by-net/$net" ]; then
	    continue
	fi

	for fname in "$base/by-net/$net/"*.fc; do
	    date=${fname%%.fc}
	    date=${date##*/}

	    local input="$base/by-net/$net/$date.fc"

	    local missing=0
	    for query in $QUERIES; do
		local out="$base/$query/$net/$date.fc"
		if [ ! -f "$out" ]; then

		    # if any query is missing, then print a message
		    # saying that we're splitting this net/date
		    # (but only print the message once per net/date,
		    # not once per query)
		    #
		    if [ $missing -eq 0 ]; then
			echo "splitting net $net for date $date"
			missing=1
		    fi

		    cat "$input" | grep ",$query$" > "$out" &

		fi
	    done
	    wait
	done
    done
}

# NETS24 is a list of all of the /24 subnets for which we have
# any data, at any time (as recorded in SUBNETDIR).
#
# If your telescope doesn't change over time, you can speed this
# up by just hardcoding the list of all of your /24s.
#
NETS24=$(cd $SUBNETDIR; cat *.txt \
	| grep /24$ \
	| sort -u \
	| sed -e 's/\/24$//')

FIRSTNET=$(echo $NETS24 | awk '{print $1}')

DATES=$(get_dates)
FC_QUERY="-t $(echo $QUERIES | sed -e 's/ / -t /g')"

PNAME=$(basename $0)

make_output_directories "$HOURLY_OUT"
echo "$PNAME: Running queries for all data"
run_hourly_queries all
echo "$PNAME: Running per-subnet queries for all data"
run_hourly_queries_per_subnet all

if [ $DO_ACKSCANS -ne 0 ]; then
    make_output_directories "$HOURLY_ACK_OUT"
    make_output_directories "$HOURLY_NACK_OUT"

    echo "$PNAME: Running queries for all data for ack scanners"
    run_hourly_queries ack
    echo "$PNAME: Running queries for all data for non-ack scanners"
    run_hourly_queries nack

    run_hourly_queries_per_subnet ack
    echo "$PNAME: Running per-subnet queries for all data for ack scanners"
    run_hourly_queries_per_subnet nack
    echo "$PNAME: Running per-subnet queries for all data for non-ack scanners"
fi

echo "$PNAME: Splitting output into per-query files"
split_by_query "$HOURLY_OUT"
