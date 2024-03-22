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

Firecracker is a tool for computing quick aggregate information about
IBR from pcap or CSV files (in supported formats).  For example,
firecracker can find the /24 subnet that sourced the most packets in a
given period of time, or find the most common protocol/dport pair in a
pcap file.

The main purpose of firecracker is to be able to perform a preliminary
analysis of IBR data as quickly as possible -- even from pcap files
that are still being captured -- to let the user spot trends or
anomalies as quickly as possible.  For example, firecracker can tell
you the most common destination port in the last hour of data in just
a few seconds for a /20-sized telescope.  Even though it is faster to
compute the same answer using other tools, such as a relational
database, these tools require a significant amount of pre-processing
time before they can process new data.

This document describes how to use firecracker, version 2023-10-16.


FIRECRACKER COMMANDLINE

1. Specifying a query

   firecracker -t PA input.pcap

  The -t parameter specifies a query, which defines which packets (or
  rows) of the input to group together.  (If no query is specified,
  the default is "PA".)

  The following fields are defined:

    S - the source address
    D - the destination address
    E - the ephemeral (source) port
    A - the application (destination) port
    P - the IP protocol
    L - the length of the IP packet (not including Ethernet headers)

  Firecracker prints the count of packets by the grouping, so "PA"
  means that firecracker will count the number of packets it observes
  with each unique protocol/application port.

  If a field name is followed by a prefix length, then only the prefix
  of the corresponding length of the value of that field is used.  For
  example, S24 means that the source addresses should be masked so
  that only the first 24 bits are used.  The default is to use all of
  the bits.  (Firecracker only supports IPv4, so this is 32 bits.)

  Note: It doesn't usually make sense to use a prefix mask for
  anything other than S (source address) and D (destination address),
  but it is legal.

2. Specifying a filter in the input

  The -F parameter is used to specify a filter:

    firecracker -F S24=146.88.240.0/P=6 -t PA input.pcap

  A filter may be specified in order to limit the records that are
  considered.  A filter consists of a list of field values, separated
  by slashes.  All of the field values must match in order for the
  record to be considered.

  This example only counts packets in input.pcap that have a source
  address within 146.88.240.0/24 and protocol 6.

3. Limiting/sorting the output

  The -m parameter is used to limit the maximum number of groupings
  that are printed:

    firecracker -m 5 -F S8=146.0.0.0/P=6 -t PA input.pcap

  This command says to print the five protocol/dport pairs for TCP
  packets with source addresses in 146.0.0.0/8 that have the highest
  counts (in descending order).

  To limit the output to the highest N counts, use the -m parameter
  with value N.  The example here will print the highest five counts,
  in descending order.

  If the value of N is 0, then no groups are printed.  The total
  number of matches (as described in the OUTPUT section) is still
  printed.

  To print all of the counts, in descending order, use N=-1.

4. Changing the time interval

  The default behavior of firecracker is to divide the input into
  15-minute chunks (starting with the timestamp on the first packet),
  and print results for each of these chunks.

  The -I N flag changes the length of the chunks to N seconds.  Note
  that N must be an integer: if there is a fractional part (i.e., 1.5)
  it will be ignored.

4. Multiple queries

  A single firecracker command can include multiple queries.  Since
  loading the input takes a long time relative to the execution time
  of most queries, in many cases it is considerably more efficient to
  batch multiple queries together than to do them separately.

  Example:

    firecracker -t PA -t P input.pcap

  This processes the PA query, and then the P query, and prints both
  results to stdout.

  See the section on the output format to see how to distinguish the
  output from each query.

  Note that there is no way to specify multiple filters or time
  intervals: all of the queries use the same filter and interval.

OTHER PARAMETERS

  -A SECONDS

    The -A parameter is used to align the time intervals over which
    the aggregates are computed.  The default is to start the time
    interval at the timestamp of the first packet, but this can cause
    problems if the input doesn't begin at an appropriate time.  For
    example, if you want to compute hourly total, then you might want
    the intervals over which those totals are computed to start and
    end at the beginning of "clock" hours to do this, use an alignment
    of 3600 (the number of seconds in an hour).

    Note that this may mean that the first interval is incomplete.
    For example, if the timestamp of the first packet is at 12:58, and
    the alignment is 3600, then the second interval will begin at
    13:00 and the first interval will only contain data for two
    minutes (not a full hour).

  -o FNAME

    Write the output to FNAME instead of stdout.

  -s TYPE

    When reading input from stdin, firecracker can't guess the type of
    input based on the name of the input file, so it assumes that the
    input is uncompressed CSV.  This parameter tells firecracker to use
    treat the input as the given TYPE, which may be one of:

      csv - for CSV data

      pcap - for PCAP data

      fc5 - for FC5 data, created by fc5conv

    Note that firecracker cannot read compressed data from stdin.

OUTPUT

The output of firecracker consists of three kinds of lines: C and T,
and an optional N, which are named after the symbol in the first field
of each line.

C lines contain counts for some grouping of fields, during a time
period, and T lines contain the total number of records that passed
through the filter (if any) for that time period.

N lines are only emitted if the user specified the -n commandline
flag, asking for "normalized" counts, with counts expressed as a
fraction of the total count.

The output lines are in CSV format, with the name of the field
preceding its value.

For example, here is a C line:

  C,9463,start_time,1634558444,P,17,A,123,S24,146.88.240.0/24

This says that there were 9463 packets in the chunk that started at
time 1634558444, that had protocol 17, application port 123, from any
source in 146.88.240.0/24.

If normalized counts are requested, and the total number of packets
(for all combinations of P, A, and S24) was 29943, then the following
"normalized" count line would also be printed:

  N,0.316033797,start_time,1634558444,P,17,A,123,S24,146.88.240.0/24

because 9463 / 29943 is 0.316033797.

Note that the values of the odd columns of the C and N lines, starting
with column 5, if concatenated together, form the query that was used
to create the line.  In this example, columns 5, 7, and 9 combine to
form PAS24, which was the query for this line.

If the -T option is given on the commandline, or if there is more than
one query specified on the commandline, then the query string is also
added as the last field on each "C" line.  This simplifies splitting
the input for each query.  In the example above, this would be
displayed as:

  C,9463,start_time,1634558444,P,17,A,123,S24,146.88.240.0/24,PAS24

And here is a T line:

  T,29943,start_time,1634558444,PAS24

This says that there were a total of 9652 packets that matched the
filter during the chunk starting at time 1634558444.  Note that every
T line has the query as the last column (whether or not the -T option
is used).

