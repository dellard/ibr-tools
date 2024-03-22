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
from scipy.interpolate import interp1d


class Feature(object):
    def __init__(self, descriptor, descriptor_type, running_features_obj):
        self.descriptor = descriptor
        self.running_features = running_features_obj
        self.feature_type = descriptor_type
        self.last_N_states = []
        self.current_state = None


    def add_new_state(self, value):
        self.last_N_states.append(value)

    def update(self, packet):
        ## Each class should implement its own
        return

    def get_state(self):
        if not self.current_state:
            raise AttributeError
        return self.current_state

    def get_last_states(self):  # TODO should this return the times too?
        return self.last_N_states

    def get_interpolated_states(self, time_values_normalized, tt):
        return interp1d(time_values_normalized, self.last_N_states)(tt)

    def get_descriptor(self):
        return self.descriptor

    def remove_first_state(self):
        self.last_N_states.pop(0)
