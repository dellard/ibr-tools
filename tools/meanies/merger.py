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
Merges "count label" input lines.

The input lines have the form "cnt label" where "label" may be any token, and
"cnt" may be any decimal integer.

The output lines have the same format as the input, except that cnt of the
output line for a given lable is the sum of all of the cnt values for that lable
in the input.

For example, if the input is

1 foo
2 foo
0 qux
3 foo
5 bar
0 qux
4 foo
6 bar

Then the output would contain only three lines:

10 foo
11 bar
0 qux
"""

import sys


def main():
    totals = dict()

    for line in sys.stdin:
        cnt_str, label = line.strip().split()
        cnt = int(cnt_str)

        if label in totals:
            totals[label] += cnt
        else:
            totals[label] = cnt

    for label in totals:
        print('%d %s' % (totals[label], label))


if __name__ == '__main__':
    main()
