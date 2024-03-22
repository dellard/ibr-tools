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

# Make a release tarball
#
# Override the RELNAME and PROJNAME as necessary.
#
# By default, the RELNAME just uses the current, local date.
# If GITTAG is set to a non-empty string, then the corresponding
# git tag, branch, or hashtag is used; the default is to use
# the local HEAD of the current branch.

RELNAME=$(date +"%Y%m%d")
PROJNAME=ibr-tools

if [ $# -gt 0 ]; then
    GITTAG="$1"
    echo "INFO: $0: using git tag [$GITTAG]"
else
    GITTAG=""
fi

SCRIPTDIR=$(dirname $(readlink -f "$0"))
RELNAME="${PROJNAME}-${RELNAME}"
TARGETDIR="/tmp/${RELNAME}"

if [ ! -z "${GITTAG}" ]; then
    git checkout "${GITTAG}"
    if [ $? -ne 0 ]; then
	echo "ERROR: $0: could not checkout ${GITTAG}"
	exit 1
    fi
fi

rm -rf "${TARGETDIR}"

# I think checkout-index might only do subdirectories, so
# we need to be at the root when we run this.
#
(cd "${SCRIPTDIR}/.." ; git checkout-index -a -f --prefix="${TARGETDIR}/")
if [ $? -ne 0 ]; then
    echo "ERROR: $0: could not checkout-index"
    exit 1
fi

# TODO: this should be optional.  If you have a good markdown viewer,
# the PDF files don't serve any useful purpose
#
"${SCRIPTDIR}/make-pdfs.sh" "${TARGETDIR}"
if [ $? -ne 0 ]; then
    echo "ERROR: $0: could not make pdfs for the README.md files"
    exit 1
fi

# Now we've created TARGETDIR with everything in it.  Now remove things
# that we do not want to be part of the release.
#
# Some of these entries are historical, and don't correspond to things
# that still exist.  TODO: prune back the list.

for unneeded in \
    utils/markings \
    params/bbn-allowed-dsts.dat params/bbn-omitted-srcs.dat \
    tools/pcap-ingestion/bbn.params \
    tools/anomaly-detection/Documentation/AnomalyDetection-SampleResults.pptx \
    tools/anomaly-detection/Documentation/AnomalyDetectionDocumentation.docx \
    tools/anomaly-detection/Documentation/anomaly-detection-documentation.docx \
    tools/anomaly-detection/Documentation/anomaly-detection-sample-results.pptx \
    tools/meanie-geo-location/greenwich-meanie-documentation.docx \
    tools/meanie-geo-location/GreenwichMeanieDocumentation.pdf \
    tools/meanie-geo-location/.ipnyb_checkpoints \
    tools/meanie-geo-location/db/full_devices_db.csv \
    tools/meanie-geo-location/db/full_geolocations_db.csv \
    ; do
    rm -rf "${TARGETDIR}"/"${unneeded}"
done

"${SCRIPTDIR}/describe-build" > "${TARGETDIR}/release-info.txt"
if [ $? -ne 0 ]; then
    echo "ERROR: $0: could not describe the release"
    exit 1
fi

(cd "${TARGETDIR}"/..; tar zcf - "${RELNAME}") > "${RELNAME}.tgz"
if [ $? -ne 0 ]; then
    echo "ERROR: $0: could not create $RELNAME.tgz"
    exit 1
fi

echo "Created ${RELNAME}.tgz"

