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

#include "firecracker.h"

/*
 * Before we add a new pkt to the chain, we need to "extend"
 * the chain to ensure that it has enough space.  Each link
 * in the chain is a pkt_chunk_t, which can hold multiple
 * packets, so we only need to actually allocate new space
 * if the chain is new (and we haven't allocated any space
 * for it at all) or if the last link in the chain is full.
 */
int
fc_extend_chain(
	pkt_chain_t *chain)
{

    if (chain->first == NULL) {
	/*
	 * If the first chunk hasn't been created yet, create it.
	 */
        pkt_chunk_t *first = (pkt_chunk_t *) malloc (sizeof (pkt_chunk_t));
	if (first == NULL) {
	    return -1;
	}

        first->next = NULL;
        first->cnt = 0;
        chain->first = first;
        chain->curr = first;
    }
    else if (chain->curr->cnt == PKTS_PER_CHUNK) {
	/*
	 * If the current chunk is full, then create a new, empty
	 * chunk to be current chunk, and link it in to the chain
	 */
        pkt_chunk_t *new_curr = (pkt_chunk_t *) malloc (sizeof (pkt_chunk_t));
	if (new_curr == NULL) {
	    return -1;
	}

        new_curr->next = NULL;
        new_curr->cnt = 0;

        chain->curr->next = new_curr;
        chain->curr = new_curr;
    }

    return 0;
}

int
pcap_free_chain(
	pkt_chain_t *chain)
{
    if (chain == NULL) {
	return 0;
    }

    pkt_chunk_t *curr = chain->first;
    while (curr != NULL) {
	pkt_chunk_t *next = curr->next;
	free(curr);
	curr = next;
    }

    return 0;
}

int
pcap_chain_to_chunk(
	pkt_chain_t *chain,
	fc_chunk_t *chunk)
{

    if (chain == NULL) {
	return 1;
    }
    if (chunk == NULL) {
	return 2;
    }

    uint64_t total_pkts = 0;
    for (pkt_chunk_t *curr = chain->first; curr != NULL; curr = curr->next) {
	total_pkts += curr->cnt;
    }

    chunk->count = total_pkts;

    /* If there aren't any packets, then we don't have much to do... */
    if (total_pkts == 0) {
	chunk->pkts = NULL;
	return 0;
    }

    chunk->pkts = (fc_pkt_t *) malloc(total_pkts * sizeof(fc_pkt_t));
    if (chunk->pkts == NULL) {
	return 3;
    }

    uint64_t curr_ind = 0;
    for (pkt_chunk_t *curr = chain->first; curr != NULL; curr = curr->next) {
	fc_pkt_t *dst = chunk->pkts + curr_ind;

	memcpy(dst, curr->pkts, curr->cnt * sizeof(fc_pkt_t));
	curr_ind += curr->cnt;
    }

    return 0;
}
