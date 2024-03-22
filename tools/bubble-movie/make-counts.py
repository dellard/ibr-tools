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
This tool creates output intended for find-max.py and plot-arcs.py.

It reads CSV input from stdin (in the form created by pcap2csv or
zeek2csv), and counts the number of each pkts from each source subnet
of the given width (by default, a /8) and the number of sources
within each source subnet that send at least one packet, for each
of the destination subnets given on the commandline.

The output has the following form: the first line starts with 'N '
and the gives a list of the destination subnets, as they were
given on the commandline.  The rest of the lines start with either
a 'P ' (for packet counts) or 'S ' (for source counts).  Each of
the 'P' and 'S' lines have the following form:

    Type SrcNet DstNet Count

Where Type is 'P' or 'S', and SrcNet is the index of the source subnet
(starting with 0, for 0.0.0.0).  DstNet is the index of the destination
network in the list given on the commandline, and Count is the count
(of the number of packets or the number of unique sources).

Note that the destination networks are not required to be the same
size as each other, and they may overlap or contain each other
(although this will usually not be the case).  The source subnets
and the destinations also don't have to be the same size (and they
usually are not).

"""

import argparse
import array
import ipaddress
import sys


class DestNetCounts:

    def __init__(self, network, src_preflen):

        self.src_preflen = src_preflen
        self.src_group_shift = (32 - src_preflen)

        self.network = network
        self.net2pkts = array.array('Q', [0] * (1 << self.src_preflen))
        self.net2srcs = [set() for i in range(1 << self.src_preflen)]
        self.minaddr = int(network.network_address)
        self.maxaddr = self.minaddr + network.num_addresses - 1

    def update(self, saddr):
        saddr_net = saddr >> self.src_group_shift

        self.net2pkts[saddr_net] += 1
        self.net2srcs[saddr_net].add(saddr)

    def counts(self, net):
        return self.net2pkts[net], len(self.net2srcs[net])


class DestNetworks:

    def __init__(self, networks, src_preflen):
        self.networks = networks
        self.netcounts = [
                DestNetCounts(networks[i], src_preflen)
                for i in range(len(networks))]

    def update(self, saddr, daddr):

        for i in range(len(self.networks)):
            net = self.netcounts[i]
            if net.minaddr <= daddr <= net.maxaddr:
                self.netcounts[i].update(saddr)

    def counts(self, net):
        return [n.counts(net) for n in self.netcounts]


def reader(networks, fin):

    for line in fin:

        saddr_str, daddr_str, _rest = line.split(',', maxsplit=2)
        saddr = int(saddr_str)
        daddr = int(daddr_str)

        networks.update(saddr, daddr)


def parse_args(argv):

    parser = argparse.ArgumentParser()

    parser.add_argument(
        '-s', dest='saddr_prefixlen',
        metavar='PREFIXLEN', default=8, type=int,
        help='Prefix length of source subnets [default=%(default)d]')

    parser.add_argument(
        'dest_networks', nargs='+', help='Destination networks')

    args = parser.parse_args(argv)

    return args.saddr_prefixlen, args.dest_networks


if __name__ == '__main__':

    def main():

        src_prefixlen, dst_names = parse_args(sys.argv[1:])

        networks = [ipaddress.IPv4Network(name) for name in dst_names]

        counters = DestNetworks(networks, src_prefixlen)

        reader(counters, sys.stdin)

        print('N %s' % ' '.join(dst_names))
        for i in range(1 << src_prefixlen):
            persource_counts = counters.counts(i)
            for dst, totals in enumerate(persource_counts):
                pkt_cnt, src_cnt = totals
                if pkt_cnt > 0:
                    print('P %d %d %d' % (i, dst, pkt_cnt))
                if src_cnt > 0:
                    print('S %d %d %d' % (i, dst, src_cnt))

    main()
