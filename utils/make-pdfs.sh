#!/usr/bin/env bash
#
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

# Create a matching PDFs for each README.md file, for people
# who prefer that way of looking at their files.
#
# prerequisites:
# install pandoc
# install texlive texlive-pdf texlive-recommended-fonts texlive-latex-extra

if [ $# -ne 1 ]; then
    echo "ERROR: usage: $0 ROOTDIRECTORY"
    exit 1
fi

ROOTDIR="$1"

if [ ! -d "$ROOTDIR" ]; then
    echo "ERROR: ROOTDIR [$ROOTDIR] does not exist or is not a directory"
    exit 1
fi

cd "$ROOTDIR"
if [ $? -ne 0 ]; then
    echo "ERROR: could not cd to ROOTDIR [$ROOTDIR]"
    exit 1
fi

ALL_README=$(find . -type f | grep "\.md$")
if [ $? -ne 0 ]; then
    echo "ERROR: could not search for markdown files"
    exit 1
fi

for source in $ALL_README; do
    dest=${source%%.md}.pdf
    echo Building $dest from $source
    pandoc -f markdown -t latex -o "$dest" "$source"

    if [ $? -ne 0 ]; then
	echo "ERROR: something went wrong"
	exit 1
    fi
done
