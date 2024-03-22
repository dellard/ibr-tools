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
Test whether IP fragments "reassemble" completely and unambiguously.

Uses the CSV representation, including the payload, for the fragments.

Reads input from stdin, writes output to stdout.

The output is also CSV, in the following format:

saddr,daddr,proto,ipid,ts,nFrags,nFirst,nFirst,nLast,nOverlap,nMissing,nDiff

saddr - source address (as a dotted quad)

daddr - destination address (as a dotted quad)

proto - IP protocol

ipid - IPID number

ts - timestamp (as a float)

nFrags - the number of fragments seen for this saddr/daddr/proto/ipid combo

nFirst - the number of 'first' fragments seen (offset == 0)

nLast - the number of 'last' fragments seen (more fragments bit == 0)

nOverlap - the number of fragments that 'overlap' with one or more other
    earlier fragments (sorted by offset).

nMissing - the number of "gaps" between fragments

    Missing "first" packets and missing "last" packets do not count as "gaps",
    and a single gap may be any length (including longer than the MTU).  We
    don't try to figure out exactly how many packets are missing, just whether
    something is missing.

nDiff - the number of fragments that have the same offset as the previous
    fragment, but have a different payload

"""

import ipaddress
import sys


class FragmentSet:
    """
    Info about a set of fragments that match the same fourtuple
    """

    def __init__(self, fourtuple):
        self.fourtuple = fourtuple
        self.timestamps = list()
        self.frags = list()

    def add(self, timestamp, offset, plen, morefrags, payload):
        """
        Add info about another fragment to the current set
        """

        self.timestamps.append(timestamp)
        self.frags.append((offset, plen, morefrags, timestamp, payload))

    def check(self):
        """
        Look at all the fragments and make some simple tests on whether
        they overlap, etc

        Returns a text string describing this set of fragments.
        """

        def offset_order(frag):
            return frag[0]

        ofrags = sorted(self.frags, key=offset_order)

        n_zero = 0
        n_last = 0
        n_overlap = 0
        n_missing = 0
        n_diff = 0

        curr_offset = ofrags[0][0]
        prev_offset = -1
        prev_payload = ''

        for i in range(len(ofrags)):
            (offset, plen, morefrags, _ts, payload) = ofrags[i]

            if offset == 0:
                n_zero += 1

            if offset < curr_offset:
                if prev_offset == offset:
                    if prev_payload != payload:
                        n_diff += 1
                n_overlap += 1
            elif offset > curr_offset:
                n_missing += 1

            prev_offset = offset
            prev_payload = payload
            curr_offset = offset + plen

            if not morefrags:
                n_last += 1

        txt = '%s,%s,%d,%d,%f' % (
                ipaddress.IPv4Address(self.fourtuple[0]),
                ipaddress.IPv4Address(self.fourtuple[1]),
                self.fourtuple[2], self.fourtuple[3],
                self.frags[0][3])
        txt += '%d,%d,%d,%d,%d,%d' % (
                len(ofrags), n_zero, n_last, n_overlap, n_missing, n_diff)

        return txt


def reassemble():
    """
    Read per-fragment info (in CSV) from stdin, write info about
    the fragment set per four-tuple (saddr/daddr/proto/ipid) to
    stdout
    """

    seen_flows = dict()

    for line in sys.stdin:
        fields = line.strip().split(',')

        saddr = int(fields[0])
        daddr = int(fields[1])
        proto = int(fields[4])
        timestamp = float(fields[5])
        plen = int(fields[6])
        ipid = int(fields[7])
        morefrags = int(fields[8])
        offset = int(fields[9])
        payload = fields[10]

        fourtuple = (saddr, daddr, proto, ipid)
        if fourtuple not in seen_flows:
            seen_flows[fourtuple] = FragmentSet(fourtuple)

        frags = seen_flows[fourtuple]
        frags.add(timestamp, offset, plen, morefrags, payload)

    for frags in seen_flows.values():
        print('%s' % frags.check())


if __name__ == '__main__':
    reassemble()
