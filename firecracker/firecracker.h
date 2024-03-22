#ifndef _FIRECRACKER_H_
#define _FIRECRACKER_H_ 1

/* CODEMARK: nice-ibr */
/*
 * Copyright (C) 2020-2024 - Raytheon BBN Technologies Corp.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 *
 * You may obtain a copy of the License at
 * http://www.apache.org/licenses/LICENSE-2.0.
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
 * either express or implied. See the License for the specific
 * language governing permissions and limitations under the License.
 *
 * Distribution Statement "A" (Approved for Public Release,
 * Distribution Unlimited).
 *
 * This material is based upon work supported by the Defense
 * Advanced Research Projects Agency (DARPA) under Contract No.
 * HR001119C0102.  The opinions, findings, and conclusions stated
 * herein are those of the authors and do not necessarily reflect
 * those of DARPA.
 *
 * In the event permission is required, DARPA is authorized to
 * reproduce the copyrighted material for use as an exhibit or
 * handout at DARPA-sponsored events and/or to post the material
 * on the DARPA website.
 */
/* CODEMARK: end */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// #include <sys/types.h>

#define MAX_LINE_LEN	(2048)

typedef struct {
    int32_t ts_sec;
    uint32_t ts_usec;
} fc_timeval_t;

typedef struct {
    uint32_t saddr;	/* destination address */
    uint32_t daddr;	/* destination address */
    uint16_t sport;	/* source port (or similar) */
    uint16_t dport;	/* destination port (or similar) */
    uint8_t proto;	/* IP proto */
    uint8_t flags; 	/* TCP flags (if applicable) */
    uint16_t len;	/* length of the original packet */
    fc_timeval_t ts;	/* packet timestamp */
} fc_pkt_t;

typedef struct {
    uint32_t value;
    uint32_t offset;
} fc_ind_entry_t;

typedef struct {
    uint64_t count;
    fc_pkt_t *pkts;
} fc_chunk_t;

/* TODO: move the low-level pcap definitions back into p25.c? */
#define PKTS_PER_CHUNK	(256 * 1024)

typedef struct pkt_chunk {
    fc_pkt_t pkts[PKTS_PER_CHUNK];
    uint64_t cnt;
    struct pkt_chunk *next;
} pkt_chunk_t;

typedef struct {
    pkt_chunk_t *first;
    pkt_chunk_t *curr;
} pkt_chain_t;

typedef enum {
    FC_INPUT_ERROR,
    FC_INPUT_PCAP,
    FC_INPUT_PCAP_GZ,
    FC_INPUT_CSV,
    FC_INPUT_CSV_GZ,
    FC_INPUT_FC5,
    FC_INPUT_FC5_GZ,
    FC_INPUT_PCAP_LZ4,
    FC_INPUT_CSV_LZ4,
    FC_INPUT_FC5_LZ4,
} fc_input_type_t;

typedef struct {
    FILE *file;
    fc_input_type_t type;
} fc_fin_t;

typedef enum {
    FC_FIELD_NAME_SADDR = 'S',
    FC_FIELD_NAME_DADDR = 'D',
    FC_FIELD_NAME_SPORT = 'E',
    FC_FIELD_NAME_DPORT = 'A',
    FC_FIELD_NAME_PROTO = 'P',
    FC_FIELD_NAME_FLAGS = 'F',
    FC_FIELD_NAME_LEN = 'L',
    FC_FIELD_NAME_SEC = 's',
    FC_FIELD_NAME_USEC = 'u',
} fc_field_name_t;

typedef struct {
    fc_field_name_t name;
    uint8_t width;
} fc_query_field_t;

/* This is much more than needed, for now */
#define FC_QUERY_MAX_FIELDS	(16)

typedef struct {
    char *query_str;
    fc_chunk_t *chunk;
    fc_query_field_t fields[FC_QUERY_MAX_FIELDS];
    fc_query_field_t groups[FC_QUERY_MAX_FIELDS];
    uint8_t n_fields;
    uint8_t n_groups;
    uint64_t show_max;
    int show_query;
} fc_query_t;

#define FC_FILTER_MAX_FIELDS	(16)

typedef struct {
    fc_field_name_t name;
    uint8_t width;
    uint32_t value;
} fc_filter_field_t;

typedef struct {
    uint8_t n_fields;
    fc_filter_field_t fields[FC_FILTER_MAX_FIELDS];
} fc_filter_t;

typedef struct {
    uint64_t *order;
    uint64_t count;
} fc_elems_t;

typedef struct {
    uint64_t base_sec;
    uint32_t length_sec;
} fc_timespan_t;


extern int fc_csv_read(
	fc_fin_t *fin, pkt_chain_t *chain, fc_filter_t *filter);
extern int fc_pcap_read(
	fc_fin_t *fin, pkt_chain_t *chain, fc_filter_t *filter);

extern fc_input_type_t find_input_type(char *fname);
extern int fc_input_open(char *fname, fc_input_type_t type, fc_fin_t *fin);
extern int fc_read_stdin(char *type, pkt_chain_t *chain, fc_filter_t *filter);
extern int fc_read_file(char *fname, pkt_chain_t *chain, fc_filter_t *filter);

extern int fc_compute_counts(
	fc_chunk_t *chunk, fc_query_t *query,
	fc_timespan_t *timespan, int normalized,
	FILE *fout);

extern void print_pkt(fc_pkt_t *pkt);

extern int fc_str2query(char *str, fc_query_t *query);

extern int fc_str2filter(char *str, fc_filter_t *filter);
extern int fc_apply_filter(
	fc_filter_t *filter, fc_chunk_t *chunk,
	uint64_t base, uint64_t count, fc_elems_t *elems);
extern int fc_filter_pkt(fc_pkt_t *pkt, fc_filter_t *filter);

extern int fc_extend_chain(pkt_chain_t *chain);
extern int pcap_chain_to_chunk(pkt_chain_t *chain, fc_chunk_t *chunk);
extern int pcap_free_chain(pkt_chain_t *chain);

extern int fc_merge_chains(
	pkt_chain_t *chains, int n_chains, fc_chunk_t *chunk);

extern uint32_t fetch_field(fc_pkt_t *pkt, fc_field_name_t name);

extern int fc_fc5_write(FILE *fout, fc_chunk_t *chunk);
extern int fc_fc5_read(
	fc_fin_t *fin, pkt_chain_t *chain, fc_filter_t *filter);

#endif /* _FIRECRACKER_H_ */
