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

# Simple example of how to create bubble movies using the tools in
# this directory.
#
# Requires that ffmpeg and gnuplot are installed.
#
# This IBR-specific example shows how to visualize information in
# four dimensions, where the dimensions represent the following:
#
# 1. Source network -- for example, each /8 in IPv4 space.
#
#   The number of source networks must be a square, because we map the
#   points into a square region (either by row-scan order, or using a
#   Hilbert or Morton space-filling curve to map the source network number
#   to an x,y pair).
#
# 2. Destination network -- for example, each /24 in an IBR telescope.
#
#   The number of destination networks should be no more than 16, and
#   preferably eight or fewer.  (Any number of networks can be supported,
#   but it is difficult to see the differences in more than about eight.)
#
# 3. The number of packets received by the destination network from
#   each source network per unit time
#
# 4. Time (in the same units).
#
# For example: the number of packets addressed from each /8 in IPv4 space
# to each /24 in a small telescope per hour.
#
# Each value is plotted as an arc, centered around an x,y point that
# represents the source network.  The extent of the arc is 360/N, where
# N is the number of destination networks, the angle of the arc represents
# the destination network, and then radius of the arc is proportional to
# the number of packets.
# 
# We can include an additional dimension by using color, but it is
# difficult to discern many colors in a complicated display.  This
# example only uses black and white.
#
# This example uses the make_counts.py program to compute the
# count of packets from each source network to each destination
# network, as described above, for each hour of data.  It also
# computes the number of unique sources within each source network
# that actually send packets, since in many cases the number of
# unique sources is a more useful metric than the number of packets.
#
# It also computes the maximum count for each value, using the
# the find-max.py utility, for the 99.5% threshold, to help
# scale the plot appropriately.  This threshold can be adjusted
# as necessary, or set to 100%.  Many of these distributions have
# long tails, so the *largest* dwarfs all of the others, making
# the plot impossible to interpret.  We set the threshold to 99.5%
# so that the scale is correct for all but the most extreme 0.5% of
# the values, which is usually a good estimate but avoids
# pathological cases.
#
# Next, this script uses bubble-example.py to create plots for
# of the hours of date: one for the packet count, and a second
# for the source count.
#
# Finally, this script uses ffmpeg (in the make_movie function)
# to construct an animation from the individual hour plots.


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
fi

if [ -z ${DATEEXPR+x} ]; then
    echo "ERROR: $PNAME: required variable DATEEXPR is not set"
    exit 1
fi

if [ -z ${SUBNETS+x} ]; then
    echo "ERROR: $PNAME: required variable SUBNETS is not set"
    exit 1
fi

if [ -z ${SPREFIXLEN+x} ]; then
    echo "ERROR: $PNAME: required variable SPREFIXLEN is not set"
    exit 1
fi

if [ -z ${CONCUR+x} ]; then
    CONCUR=4
fi

COUNTDIR=./"$DATANAME"-count-dir
PLOTDIR=./"$DATANAME"-plot-dir

if [ -z "$(which gnuplot)" ]; then
    echo "ERROR: $PNAME: gnuplot is not installed"
    exit 1
fi

if [ -z "$(which ffmpeg)" ]; then
    echo "ERROR: $PNAME: ffmpeg is not installed"
    exit 1
fi

mkdir -p $COUNTDIR $PLOTDIR
if [ $? -ne 0 ]; then
    echo "ERROR: $NAME: could not create output directories"
    exit 1
fi

get_input_files() {

    ls "$FCSVDIR/$DATANAME-$DATEEXPR"*.csv.gz
}

make_counts() {

    local cnt=0
    local fname

    for fname in $(get_input_files); do
	local hour=$(basename -s .csv.gz $fname)

	local oname="$COUNTDIR/$DATANAME-$hour.cnt"
	if [ ! -f "$oname" ]; then
	    echo "Creating counts for $hour in $oname"
	    zcat $fname \
		| "$SCRIPTDIR"/make-counts.py -s $SPREFIXLEN $SUBNETS \
		> $oname &

	    cnt=$((cnt + 1))
	    if [ $cnt -ge $CONCUR ]; then
		wait -n
	    fi
	fi
    done

    wait
}

find_maxes() {

    local maxes=$(cat $COUNTDIR/*.cnt \
	    | "$SCRIPTDIR"/find-max.py -p 99.95)
    export MAX_PKTS=$(echo $maxes | awk '{print $2}')
    export MAX_SRCS=$(echo $maxes | awk '{print $3}')
}

make_plots() {
    local plottype="$1"

    local cnt=0
    local fname
    local max

    if [ $plottype = "P" ]; then
	max=$MAX_PKTS
    else
	max=$MAX_SRCS
    fi

    for fname in "$COUNTDIR/"*.cnt; do
	local hour=$(basename -s .cnt $fname)
	local index=$(printf "%s-%.5d" $plottype $cnt)

	local outplot="$PLOTDIR/$index.jpg"

	echo "Creating plot for $hour in $outplot"
	cat $fname \
	    | "$SCRIPTDIR"/bubble-example.py \
		    -r $plottype -m $max \
		    -s $SPREFIXLEN -H -t "$hour" -p "$outplot" \
	    | gnuplot &

	cnt=$((cnt + 1))
	if [ $cnt -ge $CONCUR ]; then
	    wait -n
	fi
    done

    wait
}

make_movie() {
    local plottype="$1"

    (cd "$PLOTDIR";
	ffmpeg -loglevel error \
		-y -f image2 -framerate 25  -pattern_type sequence \
		-r 12 -i $plottype-%5d.jpg -crf 18 \
		-vcodec libx264 -pix_fmt yuv420p \
		$plottype-cnt.mp4)

    echo "Created movie $PLOTDIR/$plottype-cnt.mp4"
}


# Remove old counts
#
rm -f "$COUNTDIR"/*.cnt

# Remove old plots
#
rm -f "$PLOTDIR"/?-*.jpg

make_counts
find_maxes

make_plots P
make_plots S

make_movie P
make_movie S

