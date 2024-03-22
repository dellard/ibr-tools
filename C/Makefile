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

LIBS	= -lpcap
CFLAGS	= -g --pedantic -Wall -O3 -D_GNU_SOURCE

PROGS	= cpcap2csv filter-ip meanie2csv pcap-tsplit show-frags pktshow

default:	$(PROGS)

install:	$(PROGS)
	mkdir -p ../bin
	cp -p $(PROGS) ../bin

# If you want complete compatibility with pcap2csv timestamps,
# then add -DPCAP2CSV_COMPAT=1 to CPCAP2CSV_DEFS
CPCAP2CSV_DEFS	=
cpcap2csv:	cpcap2csv.c Makefile
	$(CC) -o $@ $(CFLAGS) $(CPACP2CSV_DEFS) cpcap2csv.c $(LIBS)

filter-ip:	filter-ip.c Makefile
	$(CC) -o $@ $(CFLAGS) filter-ip.c $(LIBS)

meanie2csv:	meanie2csv.c Makefile
	$(CC) -o $@ $(CFLAGS) meanie2csv.c $(LIBS)

pcap-tsplit:	pcap-tsplit.c Makefile
	$(CC) -o $@ $(CFLAGS) pcap-tsplit.c $(LIBS)

show-frags:	show-frags.c Makefile
	$(CC) -o $@ $(CFLAGS) show-frags.c $(LIBS)

pktshow: 	pktshow.c Makefile
	$(CC) -o $@ $(CFLAGS) pktshow.c $(LIBS)

clean:
	rm -f $(PROGS)
