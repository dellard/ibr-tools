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

SCRIPTDIR=$(dirname $(readlink -f "$0"))
PNAME="${0##*/}"

# Check that we're on a supported platform, and fail immediately
# if we're not. This software has only been tested on Ubuntu.
#
# This software MAY work without modification on other Debian-like
# distros, and can be modified to work on almost any flavor of
# contemporary Linux, but we want users to be aware that this has
# not been tested.
#
check_env() {
    local REQUIRED_DID="Ubuntu"

    echo "### Checking the local environment"

    # Check that lsb_release is available, in the path, and runs
    #
    lsb_release &> /dev/null
    if [ $? -ne 0 ]; then
        echo "ERROR: $PNAME: lsb_release failed or not found"
        echo "INFO: $PNAME: this platform is not supported"
        exit 1
    fi

    # Check the distribution id
    #
    if [[ $(lsb_release -si) != "${REQUIRED_DID}" ]]; then
        echo "ERROR: $PNAME: Linux distro [$my_dstid] not supported"
        echo "INFO: $PNAME: this platform is not supported"
        exit 1
    fi

    # Check the distribution version
    #
    local my_release=$(lsb_release -sr)
    if [ $? -ne 0 ]; then
        echo "ERROR: $PNAME: lsb_release failed"
        echo "INFO: $PNAME: this platform is not supported"
        exit 1
    fi

    # We support 18.04 for historical reasons.  Don't run on 18.04
    # if you can avoid it.  20.04 is the best release at this time.
    #
    case "$my_release" in
        18.04|20.04|22.04)
            # No changes per release right now
            ;;
        *)
            echo "ERROR: release [$my_release] not supported"
            echo "INFO: $PNAME: this platform is not supported"
            exit 1
            ;;
    esac

    return 0
}

# Give instructions for installing the prerequisites, for Ubuntu.
#
install_prereqs_ubuntu() {

    sudo apt update
    if [ $? -ne 0 ]; then
	echo "ERROR: $PNAME: could not run apt update"
	echo "FATAL: $PNAME: failed"
	exit 1
    fi

    sudo apt install \
	    build-essential python3-dev pypy3 \
	    ethtool tcpdump net-tools at \
	    libpcap-dev ffmpeg gnuplot \
	    python3-dpkt python3-pandas python3-numpy \
	    python3-scipy python3-sklearn python3-pil \
	    sqlite3 git python3-venv jupyter
    if [ $? -ne 0 ]; then
	echo "ERROR: $PNAME: could not run apt install"
	echo "FATAL: $PNAME: failed"
	exit 1
    fi

    return 0
}

# Check that we're on a supported platform, and if so, then
# attempt to install the prerequisite packages

check_env || exit 1
install_prereqs_ubuntu || exit 1

exit 0
