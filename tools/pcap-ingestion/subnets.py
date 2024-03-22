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
For a given CSV input (as created by pcap2csv or cpcap2csv, or another
tool that uses the same CSV format -- where the destination address
is given in decimal by the second column of each row), find all of the
destination /24, /20, and /16 subnets, and print them to stdout.

Input is read from stdin.

This utility can be extended to subnets of different sizes if needed.
"""


import ipaddress
import sys


def find_dst_subnets(fin):
    """
    return the set of all /24 destination subnets,
    as decimal numbers representing the base address
    of each /24, in the input CSV stream fin
    """

    seen = set()

    for line in fin:
        _saddr_s, daddr_s, _rest = line.split(',', maxsplit=2)
        seen.add(int(daddr_s) & 0xffffff00)

    return seen


def main():
    """
    Read CSV from stdin, and print out all of the /24,
    /20, and /16 destination subnets, in CIDR format, one
    per line
    """

    seen_24 = find_dst_subnets(sys.stdin)
    seen_20 = set()
    seen_16 = set()

    for addr in seen_24:
        seen_20.add(addr & 0xfffff000)
        seen_16.add(addr & 0xffff0000)

    seen_ip24 = [str(ipaddress.IPv4Address(base)) + '/24'
            for base in sorted(list(seen_24))]
    seen_ip20 = [str(ipaddress.IPv4Address(base)) + '/20'
            for base in sorted(list(seen_20))]
    seen_ip16 = [str(ipaddress.IPv4Address(base)) + '/16'
            for base in sorted(list(seen_16))]

    print('\n'.join(seen_ip24))
    print('\n'.join(seen_ip20))
    print('\n'.join(seen_ip16))


if __name__ == '__main__':
    main()
