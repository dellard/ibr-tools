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
Simple program to find the maximum (or nth percentile) values in
rows of the form created by make-counts.py, read from stdin.
The output is a single line with the form:

    M MaxPkts MaxSrcs

Where MaxPkts is the value for packets and MaxSrcs is the value
for sources, as described below.  The purpose of this program
is to find the parameters to use for make-bubbles.sh.

The default is to return the maxiumum value, but can also return
the value at the nth percentile.  For example, if the -p parameter
is 90, then the value which is greater than or equal to 90% of the
values is returned.

This program assumes that there are only two types of value
rows in the input: rows that start with an 'S' token (for
source counts) and rows that start with a 'P' token (for
packet counts).  Rows that start with any other token are
ignored.

Note: this program creates a sorted list of all of the values,
and uses this to find the nth percentile.  For simply finding
the maximum or minimum, this is very inefficient.
"""

import argparse
import sys


def reader(fin):

    all_src_cnts = list()
    all_pkt_cnts = list()

    for line in fin:
        elems = line.strip().split()
        if elems[0] == 'P':
            cnt = int(elems[3])
            all_pkt_cnts.append(cnt)
        elif elems[0] == 'S':
            cnt = int(elems[3])
            all_src_cnts.append(cnt)

    all_src_cnts.sort()
    all_pkt_cnts.sort()

    return all_pkt_cnts, all_src_cnts


def parse_args():

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-p', dest='percent',
        metavar='N', default=100, type=float,
        help='Percent of values <= the nth % [default=%(default)d]')

    return parser.parse_args()


if __name__ == '__main__':

    def main():

        args = parse_args()

        pkt_cnts, src_cnts = reader(sys.stdin)

        if args.percent >= 100:
            offset = -1
        else:
            offset = int(len(pkt_cnts) * args.percent / 100)

            # If we get rounded up to the total length, take the last
            # (I don't think this can happen, but better safe than
            # sorry)
            #
            if offset == len(pkt_cnts):
                offset = -1

        npct_pkt_cnt = pkt_cnts[offset]
        npct_src_cnt = src_cnts[offset]

        print('M %d %d' % (npct_pkt_cnt, npct_src_cnt))

    main()
