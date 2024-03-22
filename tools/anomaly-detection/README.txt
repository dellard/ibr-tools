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

Begin by reading the documents in the Documentation directory.

An example is provided here you can run after reading the
documentation.

Make sure to have installed the dependencies.

Edit the appropriate parameters in the config.yml file.

This example assumes that the input files are in the user's home
directory.  An example pcap file and csv file are included.  The csv
file was generated from the pcap file by running bin/cpcap2csv.

i.e. ../../bin/cpcap2csv < ex-2023-07-01.pcap > ex-2023-07-01.csv

So

1.  python3 -m venv venv

2.  . venv/bin/activate

3.  pip install -r requirements/requirements.txt

4. mkdir ~/csv

5. mkdir ~/anomaly-detection-results

6. cp ex-2023-07-01.csv ~/csv

7. jupyter notebook

8. Using your web browser, connect to the jupyter server (using the
   URL printed by the jupyter instance you started in the previous
   step) and open timeframe-anomaly-clustering.ipynb and run all
   cells
