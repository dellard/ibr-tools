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

# Worker program for creating a gzipped CSV file from a gzipped pcap file.


PCAPFILE="$1"
CSVFILE="$2"
FINDEX="$3"
PCAP2CSV="$4"
FILTER="$5"

CSVDIR=$(dirname "$CSVFILE")
CSVBASE=$(basename "$CSVFILE")

if [ ! -f "$CSVFILE" ]; then
    gunzip -c "$PCAPFILE" \
	    | "$PCAP2CSV" \
	    | "$FILTER" \
	    | gzip -c \
	    > "$CSVDIR/_$CSVBASE"
    if [ $? -eq 0 ]; then
	mv "$CSVDIR/_$CSVBASE" "$CSVFILE"
	exit 0
    else
	rm -f "$CSVDIR/_$CSVBASE"
	exit 1
    fi
fi
