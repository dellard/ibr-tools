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
Example application of the "bubble" plotting utility, using ArcPlot (from
plot_arcs).

"""

import argparse
import sys

from plot_arcs import ArcPlot


def reader(fin, row_prefix):
    """
    Reads lines from fin, and parse the data

    Each line consists of four whitespace-separated columns.  The first column
    defines how the rest of the line should be interpreted.  If the first column
    is 'N', then rest of the columns in the line represent the names or titles
    of the columns.  If the first column is the same as the row_prefix argument,
    then in this example the columns are interpreted as the source net (as an
    integer), destination net (as an integer), and integer value associated with
    that source and destination (such as a count of packets).  Lines that do not
    begin with row_prefix or 'N' are ignored.

    Note that this format assumes that row_prefix != 'N', and that the values
    are always positive or zero.  This is a simple illustrative example; the
    format could be changed to allow other types of values.

    The return value is a list of lists of the triples from each row (the
    second, third, and fourth columns), the list of names, and the maximum of
    any of the values in the rows.  (the latter is useful for scaling the data
    to fit the plot)

    For example, if the input looks like:

    N src dst val
    T 0 1 7
    S 1 1 1
    P 2 1 1
    T 1 2 3
    S 1 1 10
    P 4 1 0

    Then if row_prefix is 'T', then output will be

    [[0, 1, 7], [1, 2, 3]], ['src', 'dst', 'val'], 7

    or if row_prefix is 'P', then the output will be

    [[2, 1, 1], [4, 1, 0]], ['src', 'dst', 'val'], 1

    """

    names = list()
    rows = list()
    max_val = -1

    # Only do this if there's not a space...
    if not row_prefix.endswith(' '):
        row_prefix += ' ';

    for line in fin:
        if line.startswith(row_prefix):
            _rp, srcnet_s, dstnet_s, val_s = line.strip().split()
            srcnet = int(srcnet_s)
            dstnet = int(dstnet_s)
            val = int(val_s)

            if val > max_val:
                max_val = val

            rows.append((srcnet, dstnet, val))
        elif line.startswith('N '):
            names = line.strip().split()[1:]

    return rows, names, max_val


def parse_args():

    parser = argparse.ArgumentParser()

    parser.add_argument(
            '-H', dest='do_hilbert',
            default=False, action='store_true',
            help='Map source addresses using a Hilbert curve')

    parser.add_argument(
            '-M', dest='do_morton',
            default=False, action='store_true',
            help='Map source addresses using a Morton curve')

    parser.add_argument(
            '-r', dest='row_type', metavar='CHAR',
            default='P', type=str,
            help='Row type (P for pkts, S for srcs) [default=%(default)s]')

    parser.add_argument(
            '-p', dest='plot_fname', metavar='FNAME',
            default='arcplot.jpeg', type=str,
            help='Output plot file name [default=%(default)s]')

    parser.add_argument(
            '-m', dest='max_val', metavar='REAL',
            default=None, type=float,
            help='maximum value [default=max value found]')

    parser.add_argument(
            '-s', dest='n_bits', metavar='N',
            default=8, type=int,
            help='Source prefix length [default=%(default)d]')

    parser.add_argument(
            '-t', dest='title', metavar='STRING',
            default=None, type=str,
            help='Title to add to the plot [default=no title]')

    return parser.parse_args()


def morton_2d(value, nbits):
    """
    Compute the point on the two-dimensional Morton curve for
    the given value and the given number of bits in the maximum
    size of the space.

    This is also known as the "Z curve" or "Z order" (for two
    dimensions).  <https://en.wikipedia.org/wiki/Z-order_curve>

    The Morton curve is similar conceptually to the space-filling
    Hilbert curve, but makes different tradeoffs (i.e. in order
    for the average distance to be minimized, some adjacent points
    are more distant).
    """

    val_x = 0
    val_y = 0

    for i in range(nbits >> 1):
        val_x |= (value & (1 << ((2 * i) + 0))) >> (i + 0)
        val_y |= (value & (1 << ((2 * i) + 1))) >> (i + 1)

    return val_x, val_y


def main():
    args = parse_args()

    # We don't import the Hilbert library unless you've selected
    # the Hilbert mapping.  This meams that you can play around
    # with this code without installing the Hilbert library.
    #
    if args.do_hilbert:
        from hilbertcurve.hilbertcurve import HilbertCurve

        p_iter = int(args.n_bits / 2)
        hc = HilbertCurve(p_iter, 2)
        hc_points = hc.points_from_distances(range(1 << args.n_bits))

    if args.do_morton:
        morton_points = [
                morton_2d(i, args.n_bits) for i in range(1 << args.n_bits)]

    rows, dst_names, max_val = reader(sys.stdin, args.row_type)
    # FIXME: Only use this max_val if the user hasn't provided one
    if args.max_val is None:
        args.max_val = max_val

    max_x = 1 << int(args.n_bits / 2)
    max_y = max_x
    plot = ArcPlot(-2, -2, 2 + max_x, 2 + max_y, len(dst_names))

    # We map the srcnet (an integer) to a 2-d point by either
    # doing the row/column conversion (note that we assume that
    # that n_bits, which is the log2 of the number of srcnets,
    # is always even...), or using a 2-d Hilbert curve.

    for (srcnet, dstnet, val) in rows:
        if args.do_hilbert:
            pos_x, pos_y = hc_points[srcnet]
        elif args.do_morton:
            pos_x, pos_y = morton_points[srcnet]
        else:
            pos_x = srcnet & ((1 << (args.n_bits >> 1)) - 1)
            pos_y = srcnet >> (args.n_bits >> 1)

        plot.add(pos_x, pos_y, dstnet, 2 * val / args.max_val)

    print(plot.togp(term='jpeg', output=args.plot_fname, title=args.title))


if __name__ == '__main__':
    main()
