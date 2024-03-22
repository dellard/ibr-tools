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

if [ -z ${PCAPDIR+x} ]; then
    echo "ERROR: $PNAME: required variable PCAPDIR is not set"
    exit 1
elif [ ! -d "${PCAPDIR}" ]; then
    echo "ERROR: $PNAME: PCAPDIR $PCAPDIR does not exist"
    exit 1
fi

if [ -z ${FCSVDIR+x} ]; then
    echo "ERROR: $PNAME: required variable FCSVDIR is not set"
    exit 1
elif [ ! -d "${FCSVDIR}" ]; then
    echo "ERROR: $PNAME: FCSVDIR [$FCSVDIR] does not exist"
    exit 1
fi

if [ -z ${MEANIEDIR+x} ]; then
    echo "ERROR: $PNAME: required variable MEANIEDIR is not set"
    exit 1
fi
if [ ! -d "${MEANIEDIR}" ]; then
    mkdir -p "$MEANIEDIR"
    if [ $? -ne 0 ]; then
	echo "ERROR: $NAME: cannot create MEANIEDIR [$MEANIEDIR]"
	exit 1
    fi
fi

# If CONCUR is not set, give it a reasonable default
#
if [ -z ${CONCUR+x} ]; then
    CONCUR=4
fi

OUTPORTDIR="$MEANIEDIR/ports"
OUTPCAPDIR="$MEANIEDIR/pcap"
OUTTEXTDIR="$MEANIEDIR/text"
OUTSRCCNTDIR="$MEANIEDIR/src-cnts"

HSC="$SCRIPTDIR"/highest-src-cnt
PCAP2TXT="$SCRIPTDIR/../../bin/meanie2csv"
NOTEBOOKS="$SCRIPTDIR/.."
ACKSCAN_FILTER="$NOTEBOOKS/pcap-ingestion/ackscan-filter.sh"
COUNT_SRCS="$SCRIPTDIR/count-sources"

if [ ! -x "$HSC" ]; then
    echo "ERROR: $PNAME: HSC not found"
    exit 1
fi

if [ ! -x "$PCAP2TXT" ]; then
    echo "ERROR: $PNAME: PCAP2TXT not found"
    exit 1
fi

if [ ! -x "$ACKSCAN_FILTER" ]; then
    echo "ERROR: $PNAME: ACKSCAN_FILTER not found"
    exit 1
fi

if [ ! -x "$COUNT_SRCS" ]; then
    echo "ERROR: $PNAME: COUNT_SRCS not found"
    exit 1
fi

# All the days for which there are CSV files in
# the FCSVDIR
#
ALL_DAYS=$(ls "$FCSVDIR" \
	| grep csv.gz$ \
	| grep -v 2nd \
	| sed -e 's/-..\.csv\.gz//' \
	| sort -u)


# Use highest-src-cnt and some heuristics to find the
# best candidate for the port-of-the-day

find_ports() {

    mkdir -p "$OUTPORTDIR"

    local min_port=$((48 * 1024))

    local day
    local cnt=0
    for day in $ALL_DAYS; do
	if [ ! -f "$OUTPORTDIR"/"$day".txt ]; then

	    # If we don't have a complete (or at least mostly-complete)
	    # set of data for this day, then skip it.  Note: this won't
	    # help if we've already back-filled missing hours with empty
	    # files.
	    #
	    if [ $(ls "$FCSVDIR"/"$day"-??.csv.gz | wc -l) -le 20 ]; then
		echo "Skipping incompete day $day"
		continue
	    fi

	    if [ $cnt -ge $CONCUR ]; then
		wait -n
	    fi
	    cnt=$((cnt + 1))

	    # echo Starting $day

	    # We don't do ALL the daily CSV files; we just
	    # do a few hours.  This makes things faster,
	    # and works just as well because the meanie
	    # activity happens around the clock (but does
	    # seem to have a peak in the afternoon)
	    #
	    # The filter on field 4 (dport), and then sorting
	    # by the ratio of packets to sources (field 12)
	    # is a heuristic to find things that behave like
	    # the meanie "usually" behaves.  There are some
	    # other strange things that pop up from time to
	    # time
	    #
	    zcat "$FCSVDIR"/"$day"-[01][0-5].csv.gz \
		    | "$HSC" -n 10 -l 24 -p udp -t $day -c - \
		    | awk "\$4 > $min_port" | sort -n -k12 | head -1 \
		    > "$OUTPORTDIR"/"$day".txt &
	fi
    done

    wait

    (cd "$OUTPORTDIR"; chmod 444 *.txt)

}


# Given a UTC time string (in a format that date(1) likes),
# convert it to a NICE date string (YYYY-MM-DD-HH) in localtime.
#
utc_to_local() {
    local dstr="$1"
    local hour_offset="$2"

    local offset=0

    local base=$(date -u +%s --date="$dstr")
    if [ ! -z "$hour_offset" ]; then
	offset=$((hour_offset * 3600))
    fi

    date +"%Y-%m-%d-%H" --date=@$((base + offset))
}

extract_pcaps() {
    local utc_day="$1"
    local protocol="$2"
    local port="$3"
    local dnet="$4"
    local include_adjacent="$5"

    # set include_adjacent to TRUE if you want to get the
    # "adjacent" hours as well.  There are usually a handful
    # of packets that fall slightly outside the usual 24-hour
    # boundaries.  They clutter up the analysis, so omit them
    # in normal situations.

    local start_hour=0
    local end_hour=23
    if [ "$include_adjacent" = TRUE ]; then
	start_hour=-1
	end_hour=24
    fi

    local basetime=$(date +%s -u --date="$utc_day")

    local hourlist=""
    local hour=$start_hour
    local hourname

    while [ $hour -le $end_hour ]; do
	hourname=$(utc_to_local @$((basetime + (hour * 3600))))
	hourlist="$hourlist $DATANAME-$hourname.pcap.gz"
	hour=$((hour + 1))
    done

    local predicate="udp and dst port $port"
    if [ $dnet != "0/0" ]; then
	predicate="$predicate and dst net $dnet"
    fi

    mkdir -p $OUTPCAPDIR $OUTTEXTDIR

    local cnt=0
    for hourname in $hourlist; do
	local dstr=${hourname##*/}
	dstr=${dstr%.pcap.gz}

	local outpcap="$OUTPCAPDIR/$dstr-p$port.pcap"

	# Note: THIS DOES NOT filter out the acknowledged scanners!
	if [ ! -f "$outpcap" ]; then
	    gunzip -c "$PCAPDIR/$hourname" \
		    | tcpdump -r - -w "$outpcap" ${predicate} 2> /dev/null &
	fi
	cnt=$((cnt + 1))
	if [ $cnt -ge $CONCUR ]; then
	    wait -n
	fi
    done

    wait

    (cd "$OUTPCAPDIR"; chmod 444 *.pcap)
}

extract_pcaps_for_highest() {

    local tname

    for tname in "$OUTPORTDIR"/*.txt; do
	local dname=${tname##*/$DATANAME-}
	dname=${dname%.txt}

	if [ -s "$tname" ]; then
	    local port=$(cat $tname | head -1 | awk '{print $4}')
	    echo Checking fname $dname port $port
	    extract_pcaps $dname 17 $port 0/0
	fi
    done

    (cd "$OUTPCAPDIR"; chmod 444 *.pcap)
}

fill_missing() {

    # This assumes that the FCSVDIR is always complete, i.e. it
    # already has the missing files added.  If this is not true,
    # this this will fail!
    #
    # Note that we omit the last 24 names in FCSVDIR because they
    # might not be "missing"; they might simply not be complete
    # enough to find the special port for the day.
    #

    (cd $OUTTEXTDIR/; ls | grep .txt$) > $MEANIEDIR/text-listing.dat

    local fname
    for fname in $(cd "$FCSVDIR"; ls \
	    | grep csv.gz$ | grep -v 2nd | head -n -24); do
	local pref=${fname%.csv.gz}

	egrep ^"$pref-p[0-9]+.txt$" $MEANIEDIR/text-listing.dat > /dev/null
	if [ $? -ne 0 ]; then
	    local oname="$OUTTEXTDIR"/"$pref"-p0.txt
	    touch "$oname"
	    chmod 444 "$oname"
	fi
    done

    (cd "$OUTTEXTDIR"; chmod 444 *.txt)
}

pcap_to_text_day() {
    local utc_day="$1"
    local port="$2"

    if [ ! -x "$PCAP2TXT" ]; then
	echo "ERROR: missing $PCAP2TXT"
	exit 1
    fi

    mkdir -p "$OUTPCAPDIR" "$OUTTEXTDIR"

    local basetime=$(date +%s -u --date="$utc_day")

    local cnt=1
    local hour
    for (( hour=0; hour < 24; hour++)); do
	local hourname=$(utc_to_local @$((basetime + (hour * 3600))))

	local dstr=${hourname##*/}
	dstr=${dstr%.pcap}

	local inpcap="$OUTPCAPDIR/$DATANAME-$dstr-p$port.pcap"
	local outtxt="$OUTTEXTDIR/$DATANAME-$dstr-p$port.txt"

	if [ -f "$inpcap" ] && [ ! -f "$outtxt" ]; then
	    echo Creating $outtxt

	    "$PCAP2TXT" "$inpcap" \
		    | "$ACKSCAN_FILTER" -b x -F, \
		    > $outtxt &

	    cnt=$((cnt + 1))
	    if [ $cnt -gt $CONCUR ]; then
		wait -n
	    fi
	fi
    done

    wait

    (cd "$OUTTEXTDIR"; chmod 444 *.txt)
}

pcap_to_text() {

    mkdir -p "$OUTTEXTDIR"

    for tname in $OUTPORTDIR/*.txt; do
	local dname=${tname#*/$DATANAME-}
	dname=${dname%.txt}

	if [ -s "$tname" ]; then
	    local port=$(cat $tname | head -1 | awk '{print $4}')
	    echo STARTING tname $tname port $port
	    pcap_to_text_day $dname $port
	fi
    done
}

counts_per_hour() {

    local subnet="$1"
    local outdir="$2"
    local res_fname="$3"

    local subnetname=$(echo $subnet | sed -e 's/\//:/')
    local subnetdir="$outdir/$subnetname"

    echo Doing ${FUNCNAME[0]} $subnetdir

    mkdir -p "$subnetdir"

    local cnt=0
    local offset=0

    # Even though most of the subnets aren't active
    # in all of the hours, we always do every hour for
    # every subnet.  This means that we don't need to
    # figure out new xtics for every subnet when we plot
    # them.
    #
    local fname
    for fname in "$OUTTEXTDIR"/$DATANAME-*.txt ; do
	local name=${fname%.txt}
	name=${name##*/}

	local oname="$subnetdir/$name.cnt"

	if [ ! -f "$oname" ]; then
	    echo ${FUNCNAME[0]} $subnet $name

	    echo $("$COUNT_SRCS" -x -s "$subnet" "$fname") $name $offset \
		    >> "$oname" &

	    cnt=$((cnt + 1))
	    if [ $cnt -ge $CONCUR ]; then
		wait -n
	    fi
	fi

	offset=$((offset + 1))

    done

    wait

    rm -f "$res_fname"
    (cd "$subnetdir"; cat *.cnt) > "$res_fname"
}


find_ports
extract_pcaps_for_highest
pcap_to_text
fill_missing

# Compute the per-hour counts for all of the destinations (subnet
# 0.0.0.0/0) in the telescope.
#
counts_per_hour 0.0.0.0/0 "$OUTSRCCNTDIR" "$MEANIEDIR"/all_counts.txt

# If you want to do per-hour conts for any other subset of the
# telescope, add additional calls to count_per_hour, and write the
# output to a corresponding directory.  For example:
#
# counts_per_hour A.B.C.0/24 "$OUTSRCCNTDIR" "$MEANIEDIR"/counts-A.B.C.0.txt

"$SCRIPTDIR"/sources-per-hour.sh "$1"
