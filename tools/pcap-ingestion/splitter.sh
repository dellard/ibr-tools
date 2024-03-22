#!/usr/bin/env bash

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

# Split CSV files by destination subnet.
#
# The CSV files created by the ingestion process may contain packets
# addressed to more than one subnet (in many cases, there may be packets
# addressed to dozens). For some analyses, it is useful to only use
# packets addressed to a single subnet, so this utility splits the
# CSV files by destination /24 and /20, so that those analyses can run
# on the output.  If there are multiple analyses, it can save time to
# prepare these split files ahead of time.
#
# In addition, some subnets might not have data at all for some
# periods of time, and it is convenient to add empty files for those
# periods in order to make sure that the files "line up" for each
# subnet (i.e. the nth file for subnet x covers the same period
# as the nth file for subnet y).

# Instructions:
#
# This script takes a single optional commandline parameter,
# which is a file defining the parameters listed below,
# in bash syntax.
#
# These variables can also be passed in via commandline
# variables, i.e.
# FCSVDIR=bar ./splitter.sh
#
# PARAMETERS:
#
# FCSVDIR is the directory that has the CSV files with rows addressed
# to different subnets.  These are the input files.
#
# FCSVSPLIT24 is the directory where the output files for the split
# by /24.  Each output file is placed in a subdirectory of $FCSVSPLIT20
# named after the /24 prefix of the destination subnet.
#
# FCSVSPLIT20 is the directory where the output files for the split
# by /20.  Each output file is placed in a subdirectory of $FCSVSPLIT20
# named after the /20 prefix of the destination subnet.
#
# ALWAYSDIR is a subnet that we assume will always be present in
# the input files of FCSVDIR.  We assume that if we see output for
# that directory for a given hour, then the input for that hour
# has already been processed, and vice versa.  This allows us
# to avoid extra work.  Note that in our case, the prefix is
# different for /20 and /24, so we need two ALWAYSDIR addresses,
# one for each size.
#
# FIXME: there might not be an ALWAYS that works in the future.
#
# FIXME: the splitting is done in a slow, mostly-single-threaded way.
# It would increase performance quite a bit if multiple input files
# were split at the same time (up to the point where the I/O
# becomes a bottleneck).

SCRIPTDIR=$(readlink -f $(dirname "$0"))
PNAME=$(basename "$0")

if [ $# -gt 1 ]; then
    echo "ERROR: $PNAME: usage: $0 [param-file]"
    exit 1
fi

if [ $# -eq 1 ]; then
    if [ ! -r "$1" ]; then
	echo "ERROR: $PNAME: cannot read parameter file [$1]"
	exit 1
    fi

    . "$1"
    if [ $? -ne 0 ]; then
	echo "ERROR: $PNAME: bad parameter file [$1]"
	exit 1
    fi
fi

if [ -z ${FCSVDIR+x} ]; then
    echo "ERROR: $PNAME: required variable FCSVDIR is not set"
    exit 1
elif [ ! -d "${FCSVDIR}" ]; then
    echo "ERROR: $PNAME: FCSVDIR $FCSVDIR does exist"
    exit 1
fi

if [ -z ${FCSVSPLIT24+x} ]; then
    echo "ERROR: $PNAME: required variable FCSVSPLIT24 is not set"
    exit 1
elif [ ! -d "${FCSVSPLIT24}" ]; then
    mkdir -p "${FCSVSPLIT24}"
    if [ ! -d "${FCSVSPLIT24}" ]; then
	echo "ERROR: $PNAME: FCSVSPLIT24 $FCSVSPLIT24 could not be created"
	exit 1
    fi
fi

if [ -z ${FCSVSPLIT20+x} ]; then
    echo "ERROR: $PNAME: required variable FCSVSPLIT20 is not set"
    exit 1
elif [ ! -d "${FCSVSPLIT20}" ]; then
    mkdir -p "${FCSVSPLIT20}"
    if [ ! -d "${FCSVSPLIT20}" ]; then
	echo "ERROR: $PNAME: FCSVSPLIT20 $FCSVSPLIT20 could not be created"
	exit 1
    fi
fi

if [ -z ${ALWAYSDIR24+x} ]; then
    echo "ERROR: $PNAME: required variable ALWAYSDIR24 is not set"
    exit 1
fi

if [ -z ${ALWAYSDIR20+x} ]; then
    echo "ERROR: $PNAME: required variable ALWAYSDIR20 is not set"
    exit 1
fi

find_missing() {
    local targetdir="$1"

    "$SCRIPTDIR/HELPERS/find-missing.py" \
		"$FCSVDIR" .csv.gz "$targetdir" .csv.lz4
}


split_by_subnet() {
    local indir="$1"
    local outdir="$2"
    local alwaysdir="$3"
    local prefixlen="$4"

    local thisdir="$SCRIPTDIR"
    local fname
    local name
    local oname

    mkdir -p "$outdir"

    # FIXME
    # We assume that subnet $alwaysdir is ALWAYS
    # present, which won't be true someday, and then
    # we'll have to fix this.
    #
    local missing=$(find_missing "$outdir/$alwaysdir")
    for name in $missing; do
	fname="$indir/$name.csv.gz"

	if [ ! -f "$outdir/$alwaysdir/$name.csv.lz4" ]; then
	    echo Splitting $fname
	    zcat $fname \
		    | pypy3 $thisdir/HELPERS/split-by-dstnet.py \
			    "$outdir" "$name.csv" "$prefixlen"
	    # compgen is a bash utility that tells you whether a
	    # glob actually matches anything.  In this case, we're
	    # using it to find out whether splitting the input
	    # actually resulted in any output whatsoever -- for
	    # empty files, for example, it will not -- because
	    # we don't want to go through this for loop with
	    # an empty glob (it will fill the screen with
	    # warning messages).
	    #
	    if compgen -G "$outdir/*/$name.csv" > /dev/null; then
		for oname in "$outdir"/*/"$name.csv"; do
		    # echo "compressing $oname"
		    lz4 --rm -z -6 -q "$oname" "$oname.lz4" &
		done
		wait
	    fi
	fi
    done
}

# Fill in missing hours for each subnet
#
# Not all subnets were monitored at all times (some started,
# and then stopped, or were offline for some hours for other
# reasons).  For some analyses, this can can be awkward
# because things don't easily "line up" if there is data for
# a subnet for one hour and not for another hour.  So this
# function creates zero-length files for every file that
# exists in the ALWAYSDIR subnet if the corresponding file
# doesn't exist in one of the other subnets.
#
# FIXME depends on the existence of an ALWAYSDIR subnet.
# NOTE: basically a gross hack.
#
fill_splits_by_subnet() {
    local basedir="$1"
    local alwaysdir="$2"

    local dir
    local hour
    local name

    (cd $basedir &&
	for dir in */; do
	    echo "fill_by_subnet $basedir: $dir"
	    for hour in $(cd "$alwaysdir" ; ls | grep .csv.lz4$); do
		if [ ! -f "$dir/$hour" ]; then
		    name=${hour%.lz4}
		    echo "Missing $dir/$name"
		    touch "$dir/$name"
		    lz4 --rm -z -q "$dir/$name" "$dir/$name.lz4" &
		fi
	    done
	    wait
	done
    )
}


# Some hours are missing, due to connectivity problems, or hardware
# failures.  Fill them in with empty hours in the always directory
# and then use fill_by_subnet to fix the gaps in the other directories.
#
# This fixes problems in analyses that use the number of files as
# an index into the time, i.e. they assume that the tenth hour after
# a given file contains the data from ten hours after the given file.
# This won't be true if there are missing hours -- so fill them in
# with empty hours.
#
fill_alwaysdir_by_date() {
    local basedir="$1"
    local alwaysdir="$2"

    local firstname=$(basename $(cd "$basedir/$alwaysdir/"; ls | grep .csv. | head -1))
    local lastname=$(basename $(cd "$basedir/$alwaysdir/"; ls | grep .csv. | tail -1))
    #echo first $firstname last $lastname

    # Convert the filename into a valid date string
    #
    local firstdate=$(echo $firstname \
	    | sed -e "s/$DATANAME-//" -e 's/.csv.lz4$/:00/' -e 's/\(.*\)-/\1 /')
    local lastdate=$(echo $lastname \
	    | sed -e "s/$DATANAME-//" -e 's/.csv.lz4$/:00/' -e 's/\(.*\)-/\1 /')
    # echo first $firstdate last $lastdate

    # Convert the date strings into seconds since the epoch
    #
    local firstsec=$(date --date="$firstdate" +%s)
    local lastsec=$(date --date="$lastdate" +%s)
    # echo first $firstsec last $lastsec

    local start=$firstsec
    while [ $start -le $lastsec ]; do

	local name=$(date --date="@$start" +"$DATANAME-%Y-%m-%d-%H.csv.lz4")
	local fname="$basedir/$alwaysdir/$name"
	if [ ! -f "$basedir/$alwaysdir/$name" ]; then
	    echo "Missing $fname"
	    touch "${fname%.lz4}"
	    lz4 --rm -z -q "${fname%.lz4}" "$fname"
	fi

	start=$((start + 3600))
    done
}

# Some hours are missing from the fcsv-new directory, due to
# connectivity problems, or hardware failures.  Fill them in with
# empty hours.
#
# This is very similar (both in motivation and form) to
# fill_alwaysdir_by_date, except that it acts on fcsv-new itself,
# so there are no subnet directories, and the files are gzip'd
# instead of lz4'd.
#
fill_csvin_by_date() {
    local basedir="$1"

    local firstname=$(basename $(cd "$basedir/"; ls | grep .csv.gz$ | head -1))
    local lastname=$(basename $(cd "$basedir/"; ls | grep .csv.gz$ | tail -1))
    #echo first $firstname last $lastname

    # Convert the filename into a valid date string
    #
    local firstdate=$(echo $firstname \
	    | sed -e "s/$DATANAME-//" -e 's/.csv.gz$/:00/' -e 's/\(.*\)-/\1 /')
    local lastdate=$(echo $lastname \
	    | sed -e "s/$DATANAME-//" -e 's/.csv.gz$/:00/' -e 's/\(.*\)-/\1 /')
    # echo first $firstdate last $lastdate

    # Convert the date strings into seconds since the epoch
    #
    local firstsec=$(date --date="$firstdate" +%s)
    local lastsec=$(date --date="$lastdate" +%s)
    # echo first $firstsec last $lastsec

    local start=$firstsec
    while [ $start -le $lastsec ]; do

	local name=$(date --date="@$start" +"$DATANAME-%Y-%m-%d-%H.csv.gz")
	local fname="$basedir/$name"
	if [ ! -f "$basedir/$name" ]; then
	    echo "Missing $fname"
	    touch "${fname%.gz}"
	    gzip "${fname%.gz}"
	fi

	start=$((start + 3600))
    done

    chmod 444 "$basedir"/*.gz
}

# Filling by date isn't strictly necessary prior to do the
# split, but it's the same sort of operation so might as
# well do it here.
#
echo "Filling by date for $FCSVDIR"
fill_csvin_by_date "$FCSVDIR"

echo "Splitting by subnet for $FCSVSPLIT24 $ALWAYSDIR24 24"
split_by_subnet "$FCSVDIR" "$FCSVSPLIT24" "$ALWAYSDIR24" 24

echo "Filling by date for $FCSVSPLIT24 $ALWAYSDIR24"
fill_alwaysdir_by_date "$FCSVSPLIT24" "$ALWAYSDIR24"

echo "Filling by subnet for $FCSVSPLIT24 $ALWAYSDIR24"
fill_splits_by_subnet "$FCSVSPLIT24" "$ALWAYSDIR24"

# Omit the /20 subnets, for now
#
#echo "Splitting by subnet for $FCSVSPLIT20 $ALWAYSDIR24 20"
#split_by_subnet "$FCSVDIR" "$FCSVSPLIT20" "$ALWAYSDIR20" 20
#
#echo "Filling by date for $FCSVSPLIT20 $ALWAYSDIR20"
#fill_alwaysdir_by_date "$FCSVSPLIT20" "$ALWAYSDIR20"
#
#echo "Filling by subnet for $FCSVSPLIT20 $ALWAYSDIR20"
#fill_splits_by_subnet "$FCSVSPLIT20" "$ALWAYSDIR20"

# Shouldn't be necessary, but there could be a glitch in
# the alwaysdir...  So do it just in case.
