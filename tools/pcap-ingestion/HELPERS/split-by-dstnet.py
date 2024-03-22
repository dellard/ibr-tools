#!/usr/bin/env pypy3

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
Split CSV (read from sys.stdin), where the destination subnet is the second
column, and expressed in decimal (such as created by cpcap2csv or zeek2csv),
into different files, by destination subnet.

Commandline:

    split-by-dstnet.py DIR NAME PREFIXLEN

The DIR is the directory where to put the output; the NAME is the name to use
for the individual output files, and PREFIXLEN is the length of the subnet
prefix (i.e. 24 for a /24, or 16 for a /16).

Output is written to files of the form DIR/SUBNET/NAME (directories are
created if necessary).
"""


import ipaddress
import os
import sys


def make_fout(base_name, addr, out_dir, all_fout, prefixmask):
    """
    Return the correct fout to use to store the record for the
    given address.  If the file doesn't exist yet, create it
    and then return the fout for it.
    """

    addr &= prefixmask

    if addr in all_fout:
        return all_fout[addr]

    addr_s = str(ipaddress.IPv4Address(addr))
    out_base = '%s/%s' % (out_dir, addr_s)
    if not os.path.isdir(out_base):
        try:
            os.mkdir(out_base)
        except FileExistsError:
            # There may be TOCTOU issue if multiple instances
            # of this program are running concurrently, so
            # don't consider this to be an error.
            pass

    path = '%s/%s' % (out_base, base_name)

    fout = open(path, 'w+')
    all_fout[addr] = fout
    return fout


def split24(out_dir, base_name, prefixlen):
    """
    Split CSV (read from sys.stdin) into files according to
    the destination subnet for each row

    The destination subnet must be the second column of the
    the input CSV, and must be expressed in decimal.
    """

    prefixmask = 0xffffffff & (0xffffffff << (32 - prefixlen))
    all_fout = dict()

    for line in sys.stdin:
        elems = line.split(',', 2)
        daddr = int(elems[1])

        dst_fout = make_fout(
                base_name, daddr, out_dir, all_fout, prefixmask)
        dst_fout.write(line)

    for addr in all_fout:
        all_fout[addr].close()


if __name__ == '__main__':
    split24(sys.argv[1], sys.argv[2], int(sys.argv[3]))
    sys.exit(0)
