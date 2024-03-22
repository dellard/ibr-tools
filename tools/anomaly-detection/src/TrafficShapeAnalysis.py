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


import ipaddress
import pandas as pd
import numpy as np

# features imports
from .MVTSRunningFeatures import RunningFeatures
from .FeaturePacketFrequency import FeaturePacketFrequency
from .FeaturePayloadLength import FeaturePayloadLength
from .FeatureDataStringEntropy import FeatureDataStringEntropy
from .FeatureDataStringNewInformation import FeatureDataStringNewInformation
from .FeatureDataStringCosineSimilarity import FeatureDataStringCosineSimilarity
from .FeaturePortRelativeInterest import FeaturePortRelativeInterest

# Clustering imports
from math import sqrt
import numba
from sklearn.cluster import SpectralClustering, AgglomerativeClustering, MeanShift, estimate_bandwidth
from sklearn import metrics


# Can't define numba functions inside of class
@numba.jit(nopython=True, fastmath=True)
def _get_spectrum(ip_data_arr, spectrum_len):
    ip_data_len = len(ip_data_arr)
    pw_adj_mat = np.zeros(shape=(ip_data_len, ip_data_len))
    spectrum = np.zeros(shape=spectrum_len)
    for i in range(1, ip_data_len):
        pw_adj_mat[i - 1][i] = pw_adj_mat[i][i - 1] = np.linalg.norm(ip_data_arr[i] - ip_data_arr[i - 1])
    return np.linalg.eigvalsh(pw_adj_mat)[0:spectrum_len]


@numba.jit(nopython=True, fastmath=True)
def _get_spectral_distance(spectrums):
    len_spectrums = len(spectrums)
    asd_matrix = np.zeros(shape=(len_spectrums, len_spectrums))
    for i in range(len_spectrums):
        for j in range(i, len_spectrums):
            asd_matrix[i][j] = asd_matrix[j][i] = np.linalg.norm(spectrums[i] - spectrums[j])
    return asd_matrix


@numba.jit(nopython=True, fastmath=True)
def _euclidean(array_x, array_y):
    n = array_x.shape[0]
    ret = 0.
    for i in range(n):
        ret += (array_x[i] - array_y[i]) ** 2
    return sqrt(ret)


@numba.jit(nopython=True, fastmath=True)
def _hausdorff(XA, XB):
    nA = XA.shape[0]
    nB = XB.shape[0]
    cmax = 0.
    for i in range(nA):
        cmin = np.inf
        for j in range(nB):
            d = _euclidean(XA[i, :], XB[j, :])
            if d < cmin:
                cmin = d
            if cmin < cmax:
                break
        if cmax < cmin < np.inf:
            cmax = cmin
    for j in range(nB):
        cmin = np.inf
        for i in range(nA):
            d = _euclidean(XA[i, :], XB[j, :])
            if d < cmin:
                cmin = d
            if cmin < cmax:
                break
        if cmax < cmin < np.inf:
            cmax = cmin
    return cmax


class TrafficShapeAnalysis:

# Initialize and compute Features 
    def __init__(self, path_to_csv=None, csv_filenames=None, output_filename=None, destination_sources=None,
                 traffic_type=None, max_states=None, interpolation_n=None, pc_values_csv=None, show_pc_plot=False):

        # Load existing feature values if that was already provided
        if pc_values_csv:
            self.read_from_csv(pc_values_csv)
            return

        self.path_to_csv = path_to_csv
        self.csv_filenames = csv_filenames
        self.output_filename = output_filename
        self.destination_sources = destination_sources
        self.n = max_states
        self.interpolation_n = interpolation_n
        self.show_pc_plot = show_pc_plot
        self.sources_pcs_df = pd.DataFrame()

        self.dissimilarity_matrix_df = pd.DataFrame()
        self.spectral_distance_matrix_df = pd.DataFrame()
        self.cluster_df = pd.DataFrame()

        sources_features = {}  # ip -> RunningFeatures Class
        sources_pca_vals = []  # ip -> [[pca vals]]

        packet_count = 0

        # Read the specified file line by line and only keep the packets of the type specified
        for filename in csv_filenames:
            file = open(f"{path_to_csv}{filename}", 'r')
            for line in file:
                packet = line.split(',')

                if packet[2] != str(traffic_type) or \
                        str(ipaddress.ip_address(int(packet[1]))) not in destination_sources:
                    continue

                if packet_count % 1000 == 0:
                    print(f"{packet_count} packets processed", end='\r')

                pkt_time = packet[10]
                source_id = str(ipaddress.ip_address(int(packet[0])))

                if source_id not in sources_features:
                    sources_features[source_id] = self.__gen_ibr_mvts(traffic_type)
                sources_features[source_id].update(packet)

                if sources_features[source_id].get_n() > self.n + 2:
                    source_singular_values = sources_features[source_id].get_singular_values()
                    weights = np.array(source_singular_values)
                    source_pc_angle_shifts = weights * sources_features[source_id].get_pc_angles()
                    if source_pc_angle_shifts is not None:
                        sources_pca_vals.append(
                            [source_id, pkt_time] + source_singular_values + list(source_pc_angle_shifts))
                packet_count += 1

        time_features = 0
        time_interpolation = 0
        time_pca = 0
        for source_id in sources_features.keys():
            running_features = sources_features[source_id]
            time_features += running_features.time_features
            time_interpolation += running_features.time_interpolation
            time_pca += running_features.time_pca

        print(f"{packet_count} packets")
        print(f"Features time: {time_features}")
        print(f"Interpolation time: {time_interpolation}")
        print(f"PCA time: {time_pca}")

        self.sources_pcs_df = pd.DataFrame(sources_pca_vals)
        if len(self.sources_pcs_df.columns) == 12:
            self.sources_pcs_df.columns = ['ip', 'time', 'val0', 'val1', 'val2', 'val3', 'val4',
                                           'delta0', 'delta1', 'delta2', 'delta3', 'delta4']
        else:
            self.sources_pcs_df.columns = ['ip', 'port', 'time', 'val0', 'val1', 'val2', 'val3', 'val4',
                                           'delta0', 'delta1', 'delta2', 'delta3', 'delta4']
            concat_ip_port = []
            for ip, port in zip(self.sources_pcs_df['ip'], self.sources_pcs_df['port']):
                concat_ip_port.append(ip + '_' + str(port))
            del self.sources_pcs_df['port']
            self.sources_pcs_df['ip'] = concat_ip_port
        self.sources_pcs_df.set_index('time')

    def read_from_csv(self, csv_file):
        self.sources_pcs_df = pd.read_csv(csv_file)
        self.dissimilarity_matrix_df = pd.DataFrame()
        self.spectral_distance_matrix_df = pd.DataFrame()
        self.cluster_df = pd.DataFrame()

        if len(self.sources_pcs_df.columns) == 12:
            self.sources_pcs_df.columns = ['ip', 'time', 'val0', 'val1', 'val2', 'val3', 'val4', 'delta0', 'delta1',
                                           'delta2', 'delta3', 'delta4']
        else:
            self.sources_pcs_df.columns = ['ip', 'port', 'time', 'val0', 'val1', 'val2', 'val3', 'val4', 'delta0',
                                           'delta1', 'delta2', 'delta3', 'delta4']
            concat_ip_port = []
            for ip, port in zip(self.sources_pcs_df['ip'], self.sources_pcs_df['port']):
                concat_ip_port.append(ip + '_' + str(port))
            del self.sources_pcs_df['port']
            self.sources_pcs_df['ip'] = concat_ip_port
        self.sources_pcs_df.set_index('time')

    def gen_dissimilarity_matrix(self, random_sampling=True, threshold=500, col_of_interest=None):
        if col_of_interest is None:
            col_of_interest = ['val0', 'val1', 'val2', 'val3', 'val4', 'delta0', 'delta1', 'delta2',
                               'delta3', 'delta4']
        sources_vals = []
        sources = []
        for source in self.sources_pcs_df['ip'].unique():
            arr = self.sources_pcs_df[self.sources_pcs_df['ip'] == source][col_of_interest].values
            if len(arr) < 20:
                continue
            sources.append(source)
            if random_sampling and len(arr) > threshold:
                arr = arr[np.random.choice(arr.shape[0], threshold, replace=False)]
            sources_vals.append(arr)
        sources_vals_len = len(sources_vals)
        mat = np.zeros(shape=(sources_vals_len, sources_vals_len))
        for i in range(sources_vals_len):
            for j in range(i, sources_vals_len):
                if i == j or mat[i][j]:
                    continue
                mat[i][j] = mat[j][i] = self.__hausdorff_distance(sources_vals[i], sources_vals[j])
        self.dissimilarity_matrix_df = pd.DataFrame(mat, columns=sources)
        self.dissimilarity_matrix_df.index = sources

    def gen_spectral_distance_matrix(self, min_spectrum_len=5, col_of_interest=None):
        if col_of_interest is None:
            col_of_interest = ['val0', 'val1', 'val2', 'val3', 'val4', 'delta0', 'delta1', 'delta2', 'delta3', 'delta4']
        sources = [i for i in self.sources_pcs_df['ip'].unique()
                   if self.sources_pcs_df.ip.value_counts()[i] >= min_spectrum_len]
        num_sources = len(sources)
        spectrum_len = np.min([self.sources_pcs_df.ip.value_counts()[i] for i in sources])  # may be unnecessary
        spectrums = np.zeros(shape=(num_sources, spectrum_len))
        for i in range(num_sources):
            source_data_df = self.sources_pcs_df[self.sources_pcs_df['ip'] == sources[i]][col_of_interest].values
            spectrums[i] = _get_spectrum(source_data_df, spectrum_len)
        spectral_distance_matrix = _get_spectral_distance(spectrums)
        self.spectral_distance_matrix_df = pd.DataFrame(spectral_distance_matrix, columns=sources)
        self.spectral_distance_matrix_df.index = sources

    def cluster(self, clustering_type, linkage='average', n_clusters=None, distance_threshold=None, bandwidth=None,
                quantile=None, in_dict=False, labels=False, return_cluster_object=False):

        assert clustering_type in ['Agglomerative', 'MeanShift', 'Spectral'], \
            f"{clustering_type} clustering not supported. Choose 'Agglomerative', 'MeanShift', or 'Spectral'."

        mat = None
        clustering = None
        indices = None

        if clustering_type == 'Agglomerative':
            assert n_clusters or distance_threshold, \
                "Specify either n_clusters or distance_threshold for using Agglomerative clustering."
            assert linkage in ['single', 'average', 'complete'], "Linkage must be 'single', 'average', or 'complete'."

            if self.dissimilarity_matrix_df.empty:
                self.gen_dissimilarity_matrix()
            mat = self.dissimilarity_matrix_df.to_numpy()
            indices = self.dissimilarity_matrix_df.index
            clustering = AgglomerativeClustering(n_clusters=n_clusters, linkage=linkage, metric='precomputed',
                                                 distance_threshold=distance_threshold, compute_full_tree=True, compute_distances = True)

        elif clustering_type == 'MeanShift':
            assert bandwidth or quantile, "Cannot specify both bandwidth and quantile."

            if self.dissimilarity_matrix_df.empty:
                self.gen_dissimilarity_matrix()
            mat = self.dissimilarity_matrix_df.to_numpy()
            indices = self.dissimilarity_matrix_df.index

            if quantile:
                clustering = MeanShift(bandwidth=estimate_bandwidth(mat, quantile=quantile))
            elif bandwidth:
                clustering = MeanShift(bandwidth=bandwidth)
            else:
                clustering = MeanShift()

        elif clustering_type == 'Spectral':
            assert n_clusters, "n_clusters must be specified for Spectral clustering."

            if self.spectral_distance_matrix_df.empty:
                self.gen_spectral_distance_matrix()
            mat = self.spectral_distance_matrix_df.to_numpy()
            affinity_matrix = np.zeros(shape=mat.shape)
            indices = self.spectral_distance_matrix_df.index
            max_val = max([max(i) for i in mat])
            for i, row in enumerate(mat):
                for j, val in enumerate(row):
                    affinity_matrix[i][j] = 1 - (val / max_val)
            mat = affinity_matrix
            clustering = SpectralClustering(n_clusters=n_clusters, affinity='precomputed')

        cluster_labels = clustering.fit_predict(mat)
        
        #print(len(cluster_labels))
        
        new_set = [ x for i, x in enumerate(cluster_labels) if x not in cluster_labels[:i]]
        n_c = len(new_set)
        #print("No of unique items in the list are:", n_c)
        
        #print('labels: ', labels)
        
        if n_c > 1:
            print(f"Silhouette Coefficient: {metrics.silhouette_score(mat, cluster_labels)}")
            print(f"Davies-Bouldin Index: {metrics.davies_bouldin_score(mat, cluster_labels)}")
        else:
            print(f"Cannot compute Silhouette Coefficient and Davies-Bouldin Index because there is only 1 cluster")

        self.cluster_df = pd.DataFrame(np.array([indices, cluster_labels], dtype=object).T).set_index(0)
        self.cluster_object = clustering

        if in_dict:
            clust_dict = {}
            for idx in range(len(cluster_labels)):
                clust_val = cluster_labels[idx]
                ip_val = indices[idx]
                if clust_val not in clust_dict:
                    clust_dict[clust_val] = []
                clust_dict[clust_val].append(ip_val)
            return clust_dict

        if return_cluster_object:
            return clustering

        return

    @staticmethod
    def __hausdorff_distance(XA, XB):
        assert isinstance(XA, np.ndarray) and isinstance(XB, np.ndarray), \
            'arrays must be of type numpy.ndarray'
        assert np.issubdtype(XA.dtype, np.number) and np.issubdtype(XA.dtype, np.number), \
            'the arrays data type must be numeric'
        assert XA.ndim == 2 and XB.ndim == 2, \
            'arrays must be 2-dimensional'
        assert XA.shape[1] == XB.shape[1], \
            'arrays must have equal number of columns'
        return _hausdorff(XA, XB)

    def __gen_ibr_mvts(self, traffic_type):

        def udp_packet_fingerprint(packet):
            return f"{int(packet[4]):04x}{int(packet[6]):02x}"

        def tcp_packet_fingerprint(packet):
            return f"{int(packet[4]):04x}{int(packet[13]):02x}{int(packet[6]):02x}"

        def icmp_packet_fingerprint(packet):
            return f"{int(packet[4]):02x}{int(packet[6]):02x}"

        pcap_mvts = None

        if traffic_type == 17:
            pcap_mvts = RunningFeatures(udp_packet_fingerprint, traffic_type=traffic_type, memory_n=self.n,
                                        interpolation_n=self.interpolation_n, show_pc_plot=self.show_pc_plot)

            #  FEATURES TO TRACK:
            pcap_mvts.add_feature(FeaturePacketFrequency("packet_freq", traffic_type, pcap_mvts))
            pcap_mvts.add_feature(FeaturePayloadLength("payload_len", traffic_type, pcap_mvts))
            pcap_mvts.add_feature(FeatureDataStringEntropy("data_string_entropy", traffic_type, pcap_mvts))
            pcap_mvts.add_feature(FeatureDataStringNewInformation("data_string_new_info", traffic_type, pcap_mvts))
            # pcap_mvts.add_feature(FeatureDataStringCosineSimilarity("data_string_cosine_sim", traffic_type,pcap_mvts))
            pcap_mvts.add_feature(FeaturePortRelativeInterest('port_interest', traffic_type, pcap_mvts))

        elif traffic_type == 6:
            pcap_mvts = RunningFeatures(tcp_packet_fingerprint, traffic_type=traffic_type, memory_n=self.n,
                                        interpolation_n=self.interpolation_n, show_pc_plot=self.show_pc_plot)

            #  FEATURES TO TRACK:        
            pcap_mvts.add_feature(FeaturePacketFrequency("packet_freq", traffic_type, pcap_mvts))
            pcap_mvts.add_feature(FeaturePayloadLength("payload_len", traffic_type, pcap_mvts))
            pcap_mvts.add_feature(FeatureDataStringEntropy("data_string_entropy", traffic_type, pcap_mvts))
            pcap_mvts.add_feature(FeatureDataStringNewInformation("data_string_new_info", traffic_type, pcap_mvts))
            # pcap_mvts.add_feature(FeatureDataStringCosineSimilarity("data_string_cosine_sim", traffic_type, cap_mvts))
            pcap_mvts.add_feature(FeaturePortRelativeInterest('port_interest', traffic_type, pcap_mvts))

        elif traffic_type == 1:
            pcap_mvts = RunningFeatures(icmp_packet_fingerprint, traffic_type=traffic_type, memory_n=self.n,
                                        interpolation_n=self.interpolation_n, show_pc_plot=self.show_pc_plot)

            #  FEATURES TO TRACK:
            pcap_mvts.add_feature(FeaturePacketFrequency("packet_freq", traffic_type, pcap_mvts))
            pcap_mvts.add_feature(FeaturePayloadLength("payload_len", traffic_type, pcap_mvts))
            pcap_mvts.add_feature(FeatureDataStringEntropy("data_string_entropy", traffic_type, pcap_mvts))
            pcap_mvts.add_feature(FeatureDataStringNewInformation("data_string_new_info", traffic_type, pcap_mvts))
            pcap_mvts.add_feature(FeatureDataStringCosineSimilarity("data_string_cosine_sim", traffic_type, pcap_mvts))

        return pcap_mvts

    def get_sources_pcs_df(self):
        return self.sources_pcs_df

    def get_sources_pcs_csv(self, filename=None):
        if filename:
            self.sources_pcs_df.to_csv(filename, index=False)
        else:
            print("exporting")
            self.sources_pcs_df.to_csv(self.path_to_csv + self.output_filename, index=False)
