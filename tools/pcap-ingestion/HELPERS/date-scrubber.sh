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

# Given a CSV file in the format created by cpcap2csv,
# create a new CSV file (in the same format) with the
# rows containing exactly the timestamps for the hour
# named by the file.
#
# This is fairly arcane...  In the current data collection,
# the "hour" files don't always (i.e. never) begin and end
# exactly on the hour boundary implied by their names.  For
# example, the file named bbn-2021-08-30-13.csv.gz contains
# *more-or-less* the packets from 8/30/31 between 1pm and 2pm,
# but some of the packets for this hour might be in the previous
# file and/or some might slop over into the next file.  So,
# given the name of the file, we search for all the files that
# have start with the same "hour", plus the preceding and
# following files, and then search for all of these files to
# pull out all the rows that belong to that file.
#
# The TARGET is the basename name of the input and output file.
#
# The INDIR is the path to the directory to the input file,
# and OUTDIR is the path to the directory where the output
# is placed.  INDIR and OUTDIR *must* be different.

SCRIPTDIR="$(dirname "$(readlink -f "$0")")"
PNAME=$(basename "$0")

if [ $# -ne 5 ]; then
    echo "FATAL: $PNAME: usage $0 TARGET INDIR OUTDIR DATANAME TIMEZONE"
    exit 1
fi

TARGET="$1"
INDIR="$2"
OUTDIR="$3"
DATANAME="$4"
TIMEZONE="$5"

if [ $(readlink -f "$INDIR") = $(readlink -f "$OUTDIR") ]; then
    echo "FATAL: $PNAME: INDIR and OUTDIR must be different"
    exit 1
fi

HOUR=$(basename -s .csv.gz "$1")

if [ -f "$OUTDIR/$HOUR.csv.gz" ]; then
    echo "    skipping $HOUR"
    exit 0
fi

DATEEXPR=$(echo $HOUR | sed -e "s/$DATANAME-//")
if [ -z "$TIMEZONE" ]; then
    EXPR=$(python3 "$SCRIPTDIR/date-limits.py" "$DATEEXPR")
else
    EXPR=$(TZ="$TIMEZONE" python3 "$SCRIPTDIR/date-limits.py" "$DATEEXPR")
fi

if [ ! -d "$OUTDIR" ]; then
    mkdir -p "$OUTDIR"
fi

FILES=$(ls "$INDIR" | grep csv.gz$ | grep -C2 "$HOUR" )
(cd "$INDIR" ; gunzip -c $FILES \
	| awk -F, "$EXPR" \
	| gzip -c)  \
	> "$OUTDIR/$HOUR.csv.gz"

exit $?
