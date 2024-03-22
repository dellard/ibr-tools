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
import numpy as np


class FeatureDataStringNewInformation(Feature):

    def update(self, packet):
        last_packet_dist = self.running_features.get_idx_payload_dist(-1)
        if last_packet_dist:
            self.current_state = calculate_kl_divergence(self.running_features.current_payload_dist, last_packet_dist)
        else:
            self.current_state = 0
        self.add_new_state(self.current_state)


def calculate_kl_divergence(count1, count2):
    tot1 = np.sum(list(count1.values()))
    tot2 = np.sum(list(count2.values()))
    kl = 0
    for rv in set(count1).union(set(count2)):
        if count1[rv] != 0 and count2[rv] != 0:
            px = count1[rv] / tot1
            qx = count2[rv] / tot2
            kl += px * np.log(px / qx)
    return kl
