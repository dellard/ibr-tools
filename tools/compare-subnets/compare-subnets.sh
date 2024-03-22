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
# MEANIEDIR=/some/path ./compare-subnets.sh
#
# If a file is specified, the contents of the file overrides the
# values passed on the commandline.

# Required parameters:
#
# FCSVDIR is the directory containing the CSV files
#
# DATANAME is the name of the telescope
#
# SUBNETS is the list of subnets that we are comparing
#
# DATEEXPR is a regex for the input files we want to count

TMPDIR="./tmpdir"
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

if [ -z ${FCSVDIR+x} ]; then
    echo "ERROR: $PNAME: required variable FCSVDIR is not set"
    exit 1
elif [ ! -d "$FCSVDIR" ]; then
    echo "ERROR: $PNAME: FCSVDIR [$FCSVDIR] is not a directory"
    exit 1
fi

if [ -z ${SUBNETS+x} ]; then
    echo "ERROR: $PNAME: required variable SUBNETS is missing"
    exit 1
fi

if [ -z ${DATEEXPR+x} ]; then
    echo "ERROR: $PNAME: required variable DATEEXPR is missing"
    exit 1
fi


FC="$SCRIPTDIR"/../../bin/firecracker

if [ ! -x "$FC" ]; then
    echo "ERROR: $PNAME: firecracker executable missing"
    exit 1
fi


# Find the count for the top 1024 protocol/port combinations
# over the input from $inputdir/$DATANAME-$DATEEXPR, for each
# all of the data, and for each individual subnets in $SUBNETS
#
compute_counts() {
    local inputdir="$1"

    # Use a very long interval, in order to force firecracker
    # to put all of the counts into the same interval
    #
    all_seconds=$((1024 * 1024 * 4))

    cnt=0
    echo counting for all subnets all sources
    out="$TMPDIR/allnets-all.csv"
    zcat $(echo "$inputdir/$DATANAME-$DATEEXPR"*.csv.gz) \
	    | "$FC" -T -n -m 1024 -I $all_seconds \
		-t PA -o "$out" &
    cnt=$((cnt + 1))
    if [ $cnt -ge $CONCUR ]; then
	wait -n
    fi

    for subnet in $SUBNETS; do
	echo counting for subnet $subnet all sources
	out="$TMPDIR/$subnet-all.csv"
	zcat $(echo "$inputdir/$DATANAME-$DATEEXPR"*.csv.gz) \
		| "$FC" -T -n -m 1024 -I $all_seconds \
		    -F D24="$subnet" -t PA -o "$out" &
	cnt=$((cnt + 1))
	if [ $cnt -ge $CONCUR ]; then
	    wait -n
	fi

	# We're NOT doing the acknowledged/unacknowledged
	# scanners comparison in this example, but if you
	# want them, the following commented-out code
	# gives an example.  Note that this only works for
	# CSV input (not pcap), because we need to cat it
	# through ackscan-filter if we want to filter by
	# scanner type.

	#echo counting for subnet $subnet acknowledged scanners
	#filter="$SCRIPTDIR/../pcap-ingestion/ackscan-filter.sh -F, -r"
	#out="$TMPDIR/$subnet-ack.csv"
	#zcat $(echo "$FCSVDIR/$DATANAME-$DATEEXPR"*.csv.gz) \
	#	| ${filter} \
	#	| "$FC" -T -n -m 1024 -I $all_seconds \
	#		-F D24="$subnet" -t PA -o "$out" &
	#cnt=$((cnt + 1))
	#if [ $cnt -ge $CONCUR ]; then
	#    wait -n
	#fi

    done

    wait
}

# Find the protocol and application port for the n highest proto/port
# combinations, starting at the given offset, from the given
# firecracker output csv, and print each as a string of the form
# ",P,x,A,y," where x is the protocol and y is the port.  These
# strings can be grepped for in another csv file to see what the
# counts are in that file.
#
# The offset parameter is one-based so the highest value is at
# offset 1 (although due to the behavior of tail, 0 is equivalent
# to 1).
#
find_highest() {
    local csvfile="$1"
    local n="$2"
    local offset="$3"

    local highest=$(cat "$csvfile" \
	    | grep ,PA$ \
	    | tail +$offset \
	    | head -$n \
	    | awk -F, '{print ",P,"$6",A,"$8","}')

    echo -n "#"
    local pattern
    for pattern in $highest; do
	local proto=$(echo $pattern | awk -F, '{print $3}')
	local port=$(echo $pattern | awk -F, '{print $5}')

	echo -n " $proto:$port"
    done
    echo

    local subnet
    for subnet in $SUBNETS; do
	echo -n "$subnet"

	local pattern
	for pattern in $highest; do
	    local proto=$(echo $pattern | awk -F, '{print $3}')
	    local port=$(echo $pattern | awk -F, '{print $5}')

	    local count=$(cat "$TMPDIR/$subnet-all.csv" \
		    | grep ^C, | grep $pattern | awk -F, '{print $2}')
	    echo -n " $count"
	done
	echo
    done

}

# print gnuplot commands for creating a boxplot of the given
# datafile, to create a PDF in the given outfile, with the
# given title.
#
# The column titles and data titles are taken from the first
# column and first row of the data file.
#
make_plot() {
    local datafile="$1"
    local outfile="$2"
    local title="$3"

    cat << .
set term pdf size 7in,5in
set output '$outfile'
set title '$title'
set key right outside
set grid y
set style data histograms
set style histogram rowstacked
set boxwidth 0.5
set style fill solid 1.0 border -1
set ylabel "Probe Count"

plot \\
.

    arr=($(cat $datafile | head -1))
    arr=${arr[@]:1}

    cnt=2
    for col in ${arr}; do
	echo "'$datafile' using $cnt:xtic(1) title \"$col\", \\"
	cnt=$((cnt + 1))
    done

}

compute_counts "$FCSVDIR"

# Make plots for the top 8, the second 8, and the third 8
# protocol/port combinations for *all* of the input (not just
# the subnets we're plotting), from allnets-all.csv.
#
find_highest "$TMPDIR"/allnets-all.csv 8 1 > "$TMPDIR"/plot0.dat
find_highest "$TMPDIR"/allnets-all.csv 8 9 > "$TMPDIR"/plot1.dat
find_highest "$TMPDIR"/allnets-all.csv 8 17 > "$TMPDIR"/plot2.dat

# Store the gnuplot commands to temporary files, rather than
# executing them directly, so we can edit them to add better
# labels, title, etc, if necessary
#
make_plot "$TMPDIR"/plot0.dat plot0.pdf "Top eight proto/port" > t0.gp
make_plot "$TMPDIR"/plot1.dat plot1.pdf "proto/port counts 9-16" > t1.gp
make_plot "$TMPDIR"/plot2.dat plot2.pdf "proto/port counts 17-24" > t2.gp

gnuplot t0.gp
gnuplot t1.gp
gnuplot t2.gp

