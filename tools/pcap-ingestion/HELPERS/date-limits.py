#!/usr/bin/env python3

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

"""
Python script to create an awk filter to find all of the rows in CSV files
created by pcap2csv or zeek2csv that occured during a given wallclock hour.
(Any CSV file will work, as long as the eleventh column is a timestamp in
seconds.)

Takes a single argument, which is the local hour, in YYYY-mm-dd-HH format, and
writes the awk filter to stdout.  Note that the imput timestamp is always in
local time (not UTC, etc).

VERY fragile and specific to the cpcap2csv/pcap2csv CSV format.
"""

import sys
import time

from datetime import datetime

DATETIME = datetime.strptime(sys.argv[1], "%Y-%m-%d-%H")
BASESECS = time.mktime(DATETIME.timetuple())

print('$11 >= %.1f && $11 < %.1f' % (BASESECS, BASESECS + 3600))

sys.exit(0)
