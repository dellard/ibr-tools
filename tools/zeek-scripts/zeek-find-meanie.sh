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

# Script to find the meanie port for a given set of input.
#
# The meanie phenomenon is characterized by the following:
#
# 1. The probe is UDP, with a dport in the range from 48k to 64k.
#
# 2. A lot of sources, from many different areas of the network
#
# 3. A low number of probes per source (depending on the length
# of time covered by the input, and the size of the telescope,
# it may be more than 1, but often it's 1-2 probes per source per
# day.
#
# 4. The packet has a data payload, but in a small, fixed range
# (this script does not use length).
#
# So the basic heuristic is to find the destination port in the 
# range 48k-64k that has the highest number of sources from distinct
# /24 subnets, and return that.
#
# Read a zeek IBR summary CSV (computed by zeek2csv) from stdin,
# and find the most likely candidate for the meanie port for the
# corresponding day.  Note that the input is assumed to all come
# from the same "meanie day" (midnight to midnight UTC).
#
# If the input represents a lot of IBR, and is completely
# within one "meanie day", then the port output is very likely
# to be the meanie port for the day when that file .

cand=$(awk -F, '$3 == 17 && $5 >= 49152 {print int($1 / 256), $5}' \
	| sort -u \
	| awk '{print $2}' \
	| sort \
	| uniq -c \
	| sort -nr \
	| awk '{print $2}' \
	| head -1)

echo $cand

