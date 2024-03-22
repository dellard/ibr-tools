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
Print the list of names that are present in the root directory, with the
given root suffix, but are not present in the derived directory, with
the (possibly different) derived suffix.

For example, if the root directory contains the files

    a.x, b.x, c.x, d.x, e.x, f.z, g.z

and the derived directory contains the files

    a.y, b.y, c.y, d.z

the if the root suffix is ".x", then the list of names in the root
directory have have this suffix is [a, b, c, d, e], and the list
of the names in the derived directory with suffix ".y" is [a, b, c].

This means that the names "missing" from the derived directory, for
the given suffixes, are [d, e].

This is useful for figuring out what steps of the pipeline have not
been done already for a given input.  For example, one part of the
IBR pipeline turns .pcap.gz files into .csv.gz files; we can use
this program to find all .pcap.gz files for which there is no
matching .csv.gz file yet.
"""

import os
import re
import sys


def find_files(dname, filter_suffix=None, remove_suffix=False):
    """
    Return a set of all the files in the directory dname.

    If dname does not exist, or is not a directory, then return
    and empty list.

    If filter_suffix is not None, then it treated as a suffix
    string, and only filenames with the given suffix are
    considered.  If remove_suffix is True, then the filter_suffix
    is removed from each name.
    """

    if not os.path.isdir(dname):
        return list()

    fnames = [fname for fname in os.listdir(dname)
            if os.path.isfile(os.path.join(dname, fname))]

    if filter_suffix:
        fnames = [fname for fname in fnames
                if fname.endswith(filter_suffix)]

        if remove_suffix:
            fnames = [re.sub(filter_suffix, '', fname) for fname in fnames]

    return fnames


def usage():
    """
    Print a usage message
    """

    print('usage: %s ROOT ROOTSUFFIX DERIVED DERIVEDSUFFIX' % sys.argv[0])


def main():
    """
    Main function of find-missing
    """

    if len(sys.argv) != 5:
        usage()
        sys.exit(1)

    rootdir = sys.argv[1]
    root_suffix = sys.argv[2]

    deriveddir = sys.argv[3]
    derived_suffix = sys.argv[4]

    names = find_files(
            rootdir, filter_suffix=root_suffix, remove_suffix=True)
    onames = find_files(
            deriveddir, filter_suffix=derived_suffix, remove_suffix=True)

    name_set = set(names)
    oname_set = set(onames)

    difference = name_set - oname_set

    print('\n'.join(sorted(list(difference))))
    sys.exit(0)


if __name__ == '__main__':
    main()
