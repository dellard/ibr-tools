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




# Multivariate Time Series Running Features Idea
# Analyzing time window of information by applying various mathematical transformations to these multivariate
# time series dense with time-dependent information gives us the opportunity to investigate more distinguishing
# features of each source. The clustering now focuses on the behavior and values of these random variables over time.
import time
import random

# Library Imports

import nltk
import numpy as np
from collections import Counter
from sklearn import preprocessing
from sklearn.decomposition import PCA
import matplotlib.pyplot as plt

# permits access to pcap file as it is being read
import nest_asyncio

nest_asyncio.apply()

# helper functions

# Cosine Similarity
cos_sim_f = lambda a, b: np.dot(a, b) / (np.linalg.norm(a) * np.linalg.norm(b))


# one architecture: each feature be its own subclass and inherit from RunningFeatures

class RunningFeatures:

    def __init__(self, fingerprint_function, traffic_type, memory_n=100, interpolation_n=100, show_pc_plot=False):

        # self.count = 0
        self.features = []

        # Set Parameters:
        self.N = 0
        self.memory_n_threshold = memory_n
        self.interpolation_N = interpolation_n
        self.NGRAMS = 1

        self.current_payload_dist = None
        self.time = None
        self.data_str = None

        self.packet_times = []

        self.last_n_payloads = []
        self.last_n_payload_distributions = []

        # PCA Values
        self.pc_N = 5
        self.reference_pc_vector = np.ones(self.pc_N) / np.linalg.norm(np.ones(self.pc_N))
        # self.curr_pcs = None
        self.curr_singular_values = None
        self.curr_pc_angles = []

        self.fingerprint_function = fingerprint_function
        self.traffic_type = traffic_type

        self.show_pc_plot = show_pc_plot

        self.time_features = 0
        self.time_interpolation = 0
        self.time_pca = 0


    def add_feature(self, new_features):
        """
        :param new_features: list of Feature objects or a single Feature object
        :return:
        """
        try:  # case where new_features is a list
            for i_feature in new_features:
                self.features.append(i_feature)
        except TypeError:  # new_features is a single object
            self.features.append(new_features)

    def update(self, packet):

        t = time.time()
        self.time = float(packet[10])
        self.data_str = self.fingerprint_function(packet)

        self.current_payload_dist = Counter(nltk.ngrams(self.data_str, self.NGRAMS))

        # updating
        for feature in self.features:
            feature.update(packet)

        self.packet_times.append(self.time)
        self.last_n_payloads.append(self.data_str)
        self.last_n_payload_distributions.append(self.current_payload_dist)
        self.time_features += time.time() - t

        if len(self.packet_times) > self.memory_n_threshold:
            self.packet_times.pop(0)
            self.last_n_payloads.pop(0)
            self.last_n_payload_distributions.pop(0)
            for feature in self.features:  # O(2*len(self.features)) from previous for loop
                feature.remove_first_state()

            t = time.time()
            interpolated_states = self.get_interpolated_states().T
            self.time_interpolation += time.time() - t

            t = time.time()
            source_pca = PCA(n_components=self.pc_N)
            source_pca_vec = source_pca.fit_transform(interpolated_states)

            # plot PCA explained variance graph
            if self.show_pc_plot and random.uniform(0, 1) < 0.0003:
                self.plot_pca_explained_var(source_pca)

            self.curr_pc_angles = [cos_sim_f(source_pca.components_[i, :], self.reference_pc_vector) for i in
                                   range(self.pc_N)]
            self.curr_singular_values = list(source_pca.singular_values_)
            self.time_pca += time.time() - t
        self.N += 1

        return

    @staticmethod
    def plot_pca_explained_var(pca):
        source_pca_exp_var = pca.explained_variance_ratio_
        cum_sum_eigenvalues = np.cumsum(source_pca_exp_var)

        plt.bar(range(0, len(source_pca_exp_var)), source_pca_exp_var, alpha=0.5, align='center',
                label='Individual explained variance')
        plt.step(range(0, len(cum_sum_eigenvalues)), cum_sum_eigenvalues, where='mid',
                 label='Cumulative explained variance')
        plt.ylabel('Explained variance ratio')
        plt.xlabel('Principal component index')
        plt.legend(loc='best')
        plt.tight_layout()
        plt.show()

    def get_interpolated_states(self):

        interpolated_features_states = []

        time_values_normalized = np.array(self.packet_times)
        time_values_normalized = time_values_normalized - time_values_normalized[0]
        reg_tt = np.linspace(0, time_values_normalized[-1], self.interpolation_N)

        for feature in self.features:
            interpolated_feature = feature.get_interpolated_states(time_values_normalized, reg_tt)
            interpolated_features_states.append(preprocessing.normalize([interpolated_feature])[0])

        return np.array(interpolated_features_states)

    def get_singular_values(self):
        return self.curr_singular_values

    def get_pc_angles(self):
        return self.curr_pc_angles

    def get_state(self):
        return np.array([f.get_state() for f in self.features])

    def get_last_states(self):
        return np.array([f.get_last_states() for f in self.features])

    def get_memory_n(self):
        return self.memory_n_threshold

    def get_n(self):
        """
        Returns the amount of packets that used to update
        :return:
        """
        return self.N

    def get_idx_packet_time(self, n):
        try:
            return self.packet_times[n]
        except IndexError:
            return None

    def get_idx_payload_dist(self, n):
        try:
            return self.last_n_payload_distributions[n]
        except IndexError:
            return None
