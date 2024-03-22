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

from .Feature import Feature
from collections import Counter


class FeaturePortRelativeInterest(Feature):

    port_interest = Counter()
    last_n_ports = []

    def update(self, packet):
        dst_port = packet[4]

        # calculation
        if sum(self.port_interest.values()) == 0:  # TODO: epsilon threshold might be better here
            self.current_state = 0.0
        else:
            self.current_state = self.port_interest[dst_port]/sum(self.port_interest.values())
        self.add_new_state(self.current_state)

        # update
        self.port_interest.update([dst_port])
        self.last_n_ports.append(dst_port)

        if sum(self.port_interest.values()) > self.running_features.memory_n_threshold:
            first_in_port = self.last_n_ports.pop(0)
            self.port_interest[first_in_port] -= 1
