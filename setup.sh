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
# This software MAY work on other Debian-like distros, but we want
# users to be aware that this has not been tested.  It can also be
# ported to non-Debian distros, but this script doesn't support
# them.
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

build_ibr_tools() {

    echo "### Building and installing the IBR tools"

    (cd "$SCRIPTDIR"/C && make clean && make install)
    if [ $? -ne 0 ]; then
        echo "ERROR: $PNAME: build of C tools failed"
        exit 1
    fi
    (cd "$SCRIPTDIR"/firecracker; make clean; make install)
    if [ $? -ne 0 ]; then
        echo "ERROR: $PNAME: build of firecracker tools failed"
        exit 1
    fi

    return 0
}

clone_ackscan_repo() {
    # If there isn't already a copy in the users home directory,
    # then clone the acknowledge scanner database repo from gitlab.com.
    # If there is already a copy, then just make sure that it's
    # up-to-date (for the current branch).
    #
    # Some of the scripts assume that the acknowledged scanner
    # database is in $HOME/acknowledged_scanners, so if you can't
    # put it there (for any reason) then make a symlink from that
    # location to wherever it is, and remember to keep it updated.

    echo "### Getting the acknowledged scanner database repo"

    local repodir="$HOME/acknowledged_scanners"
    local url="https://gitlab.com/mcollins_at_isi/acknowledged_scanners.git"

    if [ -d "$repodir" ]; then
	echo "#### Updating the acknowledged scanner database repo"
	(cd "$repodir"; git remote update -p && git merge --ff-only "@{u}")
	if [ $? -ne 0 ]; then
	    echo "ERROR: $PNAME: fetch/merge of ackscan repo failed"
	    exit 1
	fi
    else
	echo "#### Cloning from $repo"
	(cd "$HOME"; git clone "$url")
	if [ $? -ne 0 ]; then
	    echo "ERROR: $PNAME: fetch/merge of ackscan repo failed"
	    exit 1
	fi
    fi
}

check_env || exit 1
build_ibr_tools || exit 1
clone_ackscan_repo || exit 1

exit 0
