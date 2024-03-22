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

LIB_SRC	= fc5.c p25.c c25.c input.c process.c print.c filter.c chain.c
LIB_OBJ	= $(LIB_SRC:.c=.o)

FC_SRC	= firecracker.c $(LIB_SRC)
FC_OBJ	= $(FC_SRC:.c=.o)

FC5_SRC	= fc5conv.c $(LIB_SRC)
FC5_OBJ	= $(FC5_SRC:.c=.o)

P25_SRC	= test_p25.c $(LIB_SRC)
P25_OBJ	= $(P25_SRC:.c=.o)

C25_SRC	= test_c25.c $(LIB_SRC)
C25_OBJ	= $(C25_SRC:.c=.o)

LIBS	= -lpcap
CFLAGS	= -g --pedantic -Wall -O3 -D_GNU_SOURCE

PROGS	= firecracker fc5conv

default:	$(PROGS)

install:	$(PROGS)
	cp -p $(PROGS) ../bin

test_p25:	$(P25_OBJ)
	$(CC) -o $@ $(CFLAGS) $(P25_OBJ) $(LIBS)

test_c25:	$(C25_OBJ)
	$(CC) -o $@ $(CFLAGS) $(C25_OBJ) $(LIBS)

firecracker:	$(FC_OBJ)
	$(CC) -o $@ $(CFLAGS) $(FC_OBJ) $(LIBS)

fc5conv:	$(FC5_OBJ)
	$(CC) -o $@ $(CFLAGS) $(FC5_OBJ) $(LIBS)

clean:
	rm -f $(P25_OBJ) $(C25_OBJ) $(FC_OBJ) $(FC5_OBJ) $(PROGS)

include cdepend.mk

