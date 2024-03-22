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

#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "firecracker.h"


fc_input_type_t
find_input_type(
	char *fname)
{
    size_t fname_len = strlen(fname);
    struct {
	char *suffix;
	fc_input_type_t code;
    } suffixes[] = {
	{ ".pcap", FC_INPUT_PCAP },
	{ ".pcap.gz", FC_INPUT_PCAP_GZ },
	{ ".pcap.lz4", FC_INPUT_PCAP_LZ4 },
	{ ".csv", FC_INPUT_CSV },
	{ ".csv.gz", FC_INPUT_CSV_GZ },
	{ ".csv.lz4", FC_INPUT_CSV_LZ4 },
	{ ".fc5", FC_INPUT_FC5 },
	{ ".fc5.gz", FC_INPUT_FC5_GZ },
	{ ".fc5.lz4", FC_INPUT_FC5_LZ4 },
	{ NULL, FC_INPUT_ERROR }
    };

    for (int i = 0; suffixes[i].suffix != NULL; i++) {
	char *suffix = suffixes[i].suffix;
	char suffix_len = strlen(suffix);

	if ((fname_len >= suffix_len) &&
		    !strcmp(suffix, fname + fname_len - suffix_len)) {
	    return suffixes[i].code;
	}
    }

    return FC_INPUT_ERROR;
}

int 
fc_input_open(
	char *fname,
	fc_input_type_t type,
	fc_fin_t *fin)
{

    fin->type = type;

    /* TODO: sanity checks, like whether the file even exists? */

    switch (fin->type) {
	case FC_INPUT_PCAP:
	case FC_INPUT_CSV:
	case FC_INPUT_FC5:
	    fin->file = fopen(fname, "r");
	    if (fin->file == NULL) {
		fprintf(stderr, "ERROR: could not open [%s]\n", fname);
		return -3;
	    }
	    break;
	case FC_INPUT_PCAP_GZ:
	case FC_INPUT_CSV_GZ:
	case FC_INPUT_FC5_GZ:
	case FC_INPUT_PCAP_LZ4:
	case FC_INPUT_CSV_LZ4:
	case FC_INPUT_FC5_LZ4: {
	    char *popen_template = "/usr/bin/zcat %s";

	    if (fin->type == FC_INPUT_PCAP_LZ4 ||
			fin->type == FC_INPUT_CSV_LZ4 ||
			fin->type == FC_INPUT_FC5_LZ4) {
		popen_template = "/usr/bin/lz4cat %s";
	    }

	    char *popen_cmd = malloc(strlen(popen_template) + strlen(fname));

	    if (popen_cmd == NULL) {
		fprintf(stderr, "ERROR: malloc failed\n");
		return -2;
	    }

	    sprintf(popen_cmd, popen_template, fname);
	    fin->file = popen(popen_cmd, "r");
	    free(popen_cmd); /* Might want to keep this for an error msg */

	    if (fin->file == NULL) {
		fprintf(stderr, "ERROR: could not open [%s]\n", fname);
		return -3;
	    }
	    break;
	}
	default:
	    fin->file = NULL;
	    fprintf(stderr, "ERROR: unknown input type [%s]\n", fname);
	    return -1;
    }

    return 0;
}

static int
fc_input_close(
	fc_fin_t *fin)
{

    if (fin->file == NULL) {
	return 0;
    }

    switch (fin->type) {
	case FC_INPUT_PCAP:
	case FC_INPUT_CSV:
	case FC_INPUT_FC5:
	    fclose(fin->file);
	    fin->file = NULL;
	    break;
	case FC_INPUT_PCAP_GZ:
	case FC_INPUT_CSV_GZ:
	case FC_INPUT_FC5_GZ:
	case FC_INPUT_PCAP_LZ4:
	case FC_INPUT_CSV_LZ4:
	case FC_INPUT_FC5_LZ4:
	    pclose(fin->file);
	    fin->file = NULL;
	    break;
	default:
	    fin->file = NULL;
	    return -1;
    }

    return 0;
}

int
fc_read_stdin(
	char *type,
	pkt_chain_t *chain,
	fc_filter_t *filter)
{
    fc_fin_t fin;
    int rc;

    if (type == NULL) {
	type = "csv";
    }

    /* Create a fake filename, which we can pass to
     * find_input_type.
     */
    char *fake_name = malloc(2 + strlen(type));
    sprintf(fake_name, ".%s%c", type, 0);
    fc_input_type_t fin_type = find_input_type(fake_name);
    free(fake_name);

    if (fin_type == FC_INPUT_ERROR) {
	fprintf(stderr, "ERROR: unknown stdin format [%s]\n", type);
	return -1;
    }
    else if (fin_type != FC_INPUT_PCAP && fin_type != FC_INPUT_CSV &&
	    fin_type != FC_INPUT_FC5) {
	fprintf(stderr, "ERROR: unsupported stdin format [%s]\n", type);
	return -1;
    }

    /*
     * NOTE: if the chain isn't empty, we'll end up
     * appending to it unless we reset it.
     *
     * Right now, this is always an error, but at some
     * point we might want to append chains.
     */
    fin.file = stdin;
    fin.type = fin_type;

    switch (fin_type) {
	case FC_INPUT_PCAP:
	case FC_INPUT_PCAP_GZ:
	case FC_INPUT_PCAP_LZ4: {
	    rc = fc_pcap_read(&fin, chain, filter);
	    if (rc != 0) {
		printf("pcap whoops %d\n", rc);
		return -1;
	    }
	    break;
	}
	case FC_INPUT_CSV:
	case FC_INPUT_CSV_GZ:
	case FC_INPUT_CSV_LZ4: {
	    rc = fc_csv_read(&fin, chain, filter);
	    if (rc != 0) {
		printf("csv whoops %d\n", rc);
		return -1;
	    }
	    break;
	}
	case FC_INPUT_FC5:
	case FC_INPUT_FC5_GZ:
	case FC_INPUT_FC5_LZ4: {
	    rc = fc_fc5_read(&fin, chain, filter);
	    if (rc != 0) {
		printf("fc5 whoops %d\n", rc);
		return -1;
	    }
	    break;
	}

	default:
	    fprintf(stderr, "ERROR: unknown input type [type=%d]\n",
		    fin_type);
	    return -1;
    }

    return 0;
}

int
fc_read_file(
	char *fname,
	pkt_chain_t *chain,
	fc_filter_t *filter)
{
    fc_fin_t fin;
    fc_input_type_t fin_type = find_input_type(fname);
    int rc;

    /*
     * NOTE: if the chain isn't empty, we'll end up
     * appending to it unless we reset it.
     *
     * Right now, this is always an error, but at some
     * point we might want to append chains.
     */

    rc = fc_input_open(fname, fin_type, &fin);

    switch (fin_type) {
	case FC_INPUT_PCAP:
	case FC_INPUT_PCAP_GZ:
	case FC_INPUT_PCAP_LZ4: {
	    rc = fc_pcap_read(&fin, chain, filter);
	    if (rc != 0) {
		printf("pcap whoops %d\n", rc);
		return -1;
	    }
	    break;
	}
	case FC_INPUT_CSV:
	case FC_INPUT_CSV_GZ:
	case FC_INPUT_CSV_LZ4: {
	    rc = fc_csv_read(&fin, chain, filter);
	    if (rc != 0) {
		printf("csv whoops %d\n", rc);
		return -1;
	    }
	    break;
	}
	case FC_INPUT_FC5:
	case FC_INPUT_FC5_GZ:
	case FC_INPUT_FC5_LZ4: {
	    rc = fc_fc5_read(&fin, chain, filter);
	    if (rc != 0) {
		printf("fc5 whoops %d\n", rc);
		return -1;
	    }
	    break;
	}

	default:
	    fprintf(stderr, "ERROR: unknown input type [type=%d]\n",
		    fin_type);
	    return -1;
    }

    rc = fc_input_close(&fin);
    if (rc != 0) {
	fprintf(stderr, "WARNING: could not close [%s]\n", fname);
	return -1;
    }

    return 0;
}

static inline int
ts_smaller(
	fc_timeval_t *t1,
	fc_timeval_t *t2)
{
    if (t1->ts_sec < t2->ts_sec) {
	return 1;
    }
    else if (t1->ts_sec > t2->ts_sec) {
	return 0;
    }
    else if (t1->ts_usec < t2->ts_usec) {
	return 1;
    }
    else {
	return 0;
    }
}

static int
compare_secs(
	const void *p1,
	const void *p2)
{
    fc_pkt_t *pkt1 = (fc_pkt_t *) p1;
    fc_pkt_t *pkt2 = (fc_pkt_t *) p2;

    if (pkt1->ts.ts_sec != pkt2->ts.ts_sec) {
	return pkt1->ts.ts_sec - pkt2->ts.ts_sec;
    }
    else {
	return pkt1->ts.ts_usec - pkt2->ts.ts_usec;
    }
}

int
fc_merge_chains(
	pkt_chain_t *chains,
	int n_chains,
	fc_chunk_t *chunk)
{

    /*
     * 1. Make a chunk large enough for all the chains.
     */

    uint64_t total_pkts = 0;
    for (int i = 0; i < n_chains; i++) {
	pkt_chain_t *c = &chains[i];

	for (pkt_chunk_t *curr = c->first; curr != NULL; curr = curr->next) {
	    total_pkts += curr->cnt;
	}
    }

    chunk->count = total_pkts;;

    /* If there aren't any packets, then we don't have much to do... */
    if (total_pkts == 0) {
	chunk->pkts = NULL;
	return 0;
    }

    chunk->pkts = (fc_pkt_t *) malloc(total_pkts * sizeof(fc_pkt_t));
    if (chunk->pkts == NULL) {
	fprintf(stderr, "ERROR: malloc failed\n");
	return -1;
    }

    uint64_t copied = 0;
    for (int i = 0; i < n_chains; i++) {
	pkt_chain_t *c = &chains[i];

	for (pkt_chunk_t *curr = c->first; curr != NULL; curr = curr->next) {
	    fc_pkt_t *dst = chunk->pkts + copied;

	    memcpy(dst, curr->pkts, curr->cnt * sizeof(fc_pkt_t));
	    copied += curr->cnt;
	}
    }

    qsort(chunk->pkts, copied, sizeof(fc_pkt_t), compare_secs);

    return 0;
}

/*
 * The algorithm sketched out in this routine can be significantly
 * faster than the brute-force algorithm, but it's also got some
 * subtle difficulties.  The current implementation is buggy.
 * FIXME: remove the bugs and use it instead of the slower method.
 */
int
fc_merge_chains_buggy(
	pkt_chain_t *chains,
	int n_chains,
	fc_chunk_t *chunk)
{

    /*
     * 1. Make a chunk large enough for all the chains.
     */

    uint64_t total_pkts = 0;
    for (int i = 0; i < n_chains; i++) {
	pkt_chain_t *c = &chains[i];

	for (pkt_chunk_t *curr = c->first; curr != NULL; curr = curr->next) {
	    total_pkts += curr->cnt;
	}
    }

    chunk->count = total_pkts;;

    /* If there aren't any packets, then we don't have much to do... */
    if (total_pkts == 0) {
	chunk->pkts = NULL;
	return 0;
    }

    chunk->pkts = (fc_pkt_t *) malloc(total_pkts * sizeof(fc_pkt_t));
    if (chunk->pkts == NULL) {
	fprintf(stderr, "ERROR: malloc failed\n");
	return -1;
    }

    /*
     * Special case: if there's only one chain, then just copy it
     */
    if (n_chains == 1) {
	uint64_t curr_ind = 0;
	pkt_chain_t *c = &chains[0];

	for (pkt_chunk_t *curr = c->first; curr != NULL; curr = curr->next) {
	    fc_pkt_t *dst = chunk->pkts + curr_ind;

	    memcpy(dst, curr->pkts, curr->cnt * sizeof(fc_pkt_t));
	    curr_ind += curr->cnt;
	}

	return 0;
    }

    /*
     * More complicated case: there are multiple chains, and we have
     * to merge them.  There are some nice optimizations we can make
     * if we assume that the pkt_chunks are unlikely to overlap, but
     * for the first cut we'll just do things the most simple way.
     */
    pkt_chunk_t **currs = malloc(n_chains * sizeof(pkt_chunk_t *));
    uint32_t *curr_offs = malloc(n_chains * sizeof(uint32_t *));

    if (currs == NULL) {
	fprintf(stderr, "ERROR: malloc failed\n");
	return -1;
    }
    if (curr_offs == NULL) {
	fprintf(stderr, "ERROR: malloc failed\n");
	return -1;
    }

    for (int i = 0; i < n_chains; i++) {
	currs[i] = chains[i].first;
	curr_offs[i] = 0;
    }

    for (uint64_t indx = 0; indx < total_pkts; indx++) {
	fc_timeval_t smallest_ts = { 0x7fffffff, 0 };
	fc_pkt_t *candidate = NULL;
	int candidate_chain = -1;

	for (int i = 0; i < n_chains; i++) {
	    if (currs[i] != NULL) {

		/*
		 * If we've already reached the end of the chunk,
		 * move to the next
		 */
		if (curr_offs[i] >= currs[i]->cnt) {
		    currs[i] = currs[i]->next;
		    curr_offs[i] = 0;

		    if (currs[i] == NULL) {
			continue;
		    }
		}

		fc_pkt_t *pkt = &currs[i]->pkts[curr_offs[i]];

		if (ts_smaller(&pkt->ts, &smallest_ts)) {
		    candidate = pkt;
		    candidate_chain = i;
		}
	    }
	}

	chunk->pkts[indx] = *candidate;
	if (candidate_chain < 0) {
	    printf("oops - candidate chain\n");
	}

	curr_offs[candidate_chain]++;
    }

    free(currs);
    free(curr_offs);

    return 0;
}
