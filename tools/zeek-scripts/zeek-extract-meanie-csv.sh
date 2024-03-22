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

# Given a directory of CSV files (created by zeek2csv or pcap2csv)
# in $ZEEK_CSVDIR, and information about the meanie port for each day
# (in the $ZEEK_MEANIE_PORTS file), extract just the CSV rows for the
# corresponding meanie port and put them in the output directory
# ($ZEEK_MEANIE_CSVDIR).


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

if [ -z "$ZEEK_CSVDIR" ]; then
    echo "ERROR: no ZEEK_LOGDIR specified"
    exit 1
fi

if [ -z "$ZEEK_MEANIE_CSVDIR" ]; then
    echo "ERROR: no ZEEK_MEANIE_CSVDIR specified"
    exit 1
fi

if [ -z "$ZEEK_DATE_REGEX" ]; then
    echo "ERROR: no ZEEK_DATE_REGEX specified"
    exit 1
fi

if [ -z "$ZEEK_MEANIE_PORTS" ]; then
    echo "ERROR: no ZEEK_MEANIE_PORTS specified"
    exit 1
fi

# Given a UTC time string (in a format that date(1) likes),
# convert it to a NICE date string (YYYY-MM-DD/conn.HH)
# in localtime.
#
utc_to_local() {
    local dstr="$1"
    local hour_offset="$2"

    local offset=0

    local base=$(date -u +%s --date="$dstr")
    if [ ! -z "$hour_offset" ]; then
        offset=$((hour_offset * 3600))
    fi

    date +"%Y-%m-%d/conn.%H" --date=@$((base + offset))
}

# Given a time string (in a format that date(1) likes),
# in localtime, convert it to a NICE date string
# (YYYY-MM-DD/conn.HH) in UTC.
#
local_to_utc() {
    local dstr="$1"
    local hour_offset="$2"

    local offset=0

    local base=$(date +%s --date="$dstr")
    if [ ! -z "$hour_offset" ]; then
        offset=$((hour_offset * 3600))
    fi

    date -u +"%Y-%m-%d/conn.%H" --date=@$((base + offset))
}

extract_meanie() {
    local in_fname="$1"
    local port="$2"
    local out_fname="$3"
    local file_reader="$4"

    if [ ! -f "$out_fname" ]; then
	echo "Creating $out_fname"
	"$file_reader" "$in_fname" \
		| awk -F, "\$3 == 17 && \$5 == $port" \
		> "$out_fname"
    fi
}

find_meanie_csv() {
    local indir="$1"
    local outdir="$2"
    local date_regex="$3"
    local mport_file="$4"

    mkdir -p "$outdir"

    local dir
    local incsv
    local reader

    for incsv in $(ls "$indir"/"$ZEEK_DATANAME-$date_regex"* ) ; do
	local hname=${incsv##*/}
	hname=${hname%%.csv.gz}

	local hour=${hname##*-}
	local day=${hname%-??}
	# echo date $day hour $hour

	if [[ "$incsv" =~ .gz ]]; then
	    reader=zcat
	else
	    reader=cat
	fi

	local utc_date=$(echo $(local_to_utc "$day $hour:00") \
		| sed -e 's/\/.*$//')
	local meanie_port=$(cat "$mport_file" \
		| grep $utc_date | awk '{print $1}')
	if [ -z "$meanie_port" ]; then
	    echo "MISSING PORT for $utc_date"
	else
	    # echo utc_date $utc_date $hour port "$meanie_port"
	    local out="$outdir/$ZEEK_DATANAME-$day-$hour-p$meanie_port.csv"
	    extract_meanie "$incsv" "$meanie_port" "$out" "$reader"
	fi
    done

    chmod 444 "$outdir"/*.csv
}

find_meanie_csv "$ZEEK_CSVDIR" "$ZEEK_MEANIE_CSVDIR" \
	"$ZEEK_DATE_REGEX" "$ZEEK_MEANIE_PORTS"
