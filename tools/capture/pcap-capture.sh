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

# Capture packets, in pcap format, from a given interface, and place
# the files into a given directory, using tcpdump.  Tcpdump will
# create a new pcap file for each file, and each file will have
# a name of the form $DATANAME-YYYY-MM-DD-HH.pcap, where DATANAME
# is the name of the dataset (see below, and the documentation for
# the parameter files), YYYY is the year, MM is the month, DD is
# the day of the month, and HH is the hour.
#
# Note that the date is expressed in the local time (as configured
# for the host this script is running on), unless overridden by the
# TIMEZONE parameter.
#
# Instructions:
#
# This script takes a single optional commandline parameter, which
# is a file defining the parameters listed below, in bash syntax.
#
# These variables can also be passed in via commandline variables,
# i.e.
#
# IFACE=eth0 PCAPDIR=/some/path DATANAME=mynetwork ./pcap-capture.sh
#
# If a file is specified, the values in the file override the values
# passed on the commandline.
#
# Parameters:
#
# PCAPDIR - the path to a directory where the output pcap files created
# by this script are stored.
#
# PCAPRAWDIR - an optional parameter.  If PCAPRAWDIR is defined, it
# overrides the value of PCAPDIR (if any).  At least one of PCAPDIR and
# PCAPRAWDIR must be defined.
#
# IFACE - the interface from which the packets are captured (usually
# a name like "eth0", or "eno0" or "enp0s1f1", but the exact name
# depends on the type of interface you have).
#
# DATANAME - the name of the dataset that you are collecting.  The
# names of the pcap files created by this script will start with
# $DATANAME.
#
# TIMEZONE - an optional parameter.  Defines the timezone to use for
# names of the dates (e.g., "EST" or "UTC").  The default is to use
# the default timezone that the local system is configured to use.
# (If the TIMEZOME implements daylight savings time, then the capture
# will appear to skip an hour in the Spring, and lose an hour of
# data in the Fall.)


SCRIPTDIR=$(readlink -f $(dirname "$0"))
PNAME=$(basename "$0")

if [ $# -gt 1 ]; then
    echo "ERROR: usage: $0 [param-file]"
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

if [ ! -z "${PCAPRAWDIR}" ]; then
    OUTPUTDIR="$PCAPRAWDIR"
elif [ ! -z "${PCAPDIR}" ]; then
    OUTPUTDIR="$PCAPDIR"
else
    echo "ERROR: $PNAME: neither PCAPDIR nor PCAPRAWDIR set"
    exit 1
fi

if [ -z "${IFACE}" ]; then
    echo "ERROR: $PNAME: IFACE is not set"
    exit 1
fi

if [ -z ${DATANAME+x} ]; then
    echo "ERROR: $PNAME: required variable DATANAME is not set"
    exit 1
fi

if [ -z ${TIMEZONE+x} ]; then
    TIMEZONE=""
fi

echo "$PNAME: PCAP output directory will be $OUTPUTDIR"

# Make sure that the user can get sudo.
# We don't want to interfere with the timing later by
# having to ask for their password again.
#
/usr/bin/sudo true
if [ $? -ne 0 ]; then
    echo "ERROR: $PNAME: sudo permissions required."
    exit 1
fi

if [ ! -d "$OUTPUTDIR" ]; then
    mkdir -p "$OUTPUTDIR"
    if [ $? -ne 0 ]; then
	echo "ERROR: $PNAME: cannot create OUTPUTDIR [$OUTPUTDIR]"
	exit 1
    fi
    chmod 755 "$OUTPUTDIR"
fi

# Set the interface options to prevent TCP segment offloading, etc.
# This ensures that we get the packets as they appeared on the wire.
# This usually won't matter for IBR, but there are cases where it does.
#
/usr/bin/sudo ethtool -K "$IFACE" \
	rx off tx off tso off ufo off gso off gro off lro off
if [ $? -ne 0 ]; then
    echo "ERROR: $PNAME: could not set interface options"
    exit 1
fi

# We may need OUTPUTDIR to be an absolute path in some cases,
# so find its absolute path now.
#
OUTPUTDIR=$(readlink -f "$OUTPUTDIR")
NAMEEXPR="$OUTPUTDIR/$DATANAME-%F-%H.pcap"

# Figure out the date of the start of the next hour, in
# "at" timespec notation.  To do this, we find the current
# date in seconds (since the epoch), and then add 3600
# to this to move it an hour ahead (FUTUREHOUR), and then
# use the date command to find the name of this hour in
# the format that the "at" command uses (ATTIME).
#
# Then use "at" to schedule tcpdump to start at $ATTIME,
# running as sudo.
#
FUTUREHOUR=$(( 3600 + $(date +%s) ))
ATTIME=$(date --date=@"$FUTUREHOUR" +"%H:00 %Y-%m-%d")

if [ ! -z "$TIMEZONE" ]; then
    echo TZ=$TIMEZONE tcpdump -s0 -Z root \
		-i \"$IFACE\" -w \"$NAMEEXPR\" -G 3600 ip \
	    | /usr/bin/sudo /usr/bin/at "$ATTIME"
    if [ $? -ne 0 ]; then
	echo "ERROR: $PNAME: scheduling failed"
	exit 1
    fi
else
    echo tcpdump -s0 -Z root \
		-i \"$IFACE\" -w \"$NAMEEXPR\" -G 3600 ip \
	    | /usr/bin/sudo /usr/bin/at "$ATTIME"
    if [ $? -ne 0 ]; then
	echo "ERROR: $PNAME: scheduling failed"
	exit 1
    fi
fi

echo "$PNAME: the capture will begin at the start of the next hour"
