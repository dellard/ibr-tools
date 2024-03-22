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

#include <arpa/inet.h>

#include "firecracker.h"

int
fc_fc5_read(
	fc_fin_t *fin,
	pkt_chain_t *chain,
	fc_filter_t *filter)
{
    int rc;

    chain->first = NULL;
    chain->curr = NULL;

    for (;;) {
	fc_pkt_t new_pkt;

	size_t n_read = fread(&new_pkt, sizeof(fc_pkt_t), 1, fin->file);
	if (n_read != 1) {
	    break;
	}

	rc = fc_extend_chain(chain);
	if (rc != 0) {
	    pcap_free_chain(chain);
	    return 1;
	}

	uint32_t curr_cnt = chain->curr->cnt;
	fc_pkt_t *pkt = &chain->curr->pkts[curr_cnt];

	pkt->saddr = ntohl(new_pkt.saddr);
	pkt->daddr = ntohl(new_pkt.daddr);
	pkt->sport = ntohs(new_pkt.sport);
	pkt->dport = ntohs(new_pkt.dport);
	pkt->proto = new_pkt.proto;
	pkt->flags = new_pkt.flags;
	pkt->len = ntohs(new_pkt.len);
	pkt->ts.ts_sec = ntohl(new_pkt.ts.ts_sec);
	pkt->ts.ts_usec = ntohl(new_pkt.ts.ts_usec);

	/* If there's a filter, and it doesn't match this packet,
	 * then don't increment the current count.  Just ignore
	 * this packet
	 */
	if ((filter == NULL) || fc_filter_pkt(pkt, filter)) {
	    chain->curr->cnt++;
	}
    }

    return 0;
}

int
fc_fc5_write(
	FILE *fout,
	fc_chunk_t *chunk)
{

    for (uint64_t i = 0; i < chunk->count; i++) {
	fc_pkt_t *pkt = &chunk->pkts[i];
	fc_pkt_t new_pkt;

	new_pkt.saddr = ntohl(pkt->saddr);
	new_pkt.daddr = ntohl(pkt->daddr);
	new_pkt.sport = ntohs(pkt->sport);
	new_pkt.dport = ntohs(pkt->dport);
	new_pkt.proto = pkt->proto;
	new_pkt.flags = pkt->flags;
	new_pkt.len = ntohs(pkt->len);
	new_pkt.ts.ts_sec = ntohl(pkt->ts.ts_sec);
	new_pkt.ts.ts_usec = ntohl(pkt->ts.ts_usec);

	size_t n_written = fwrite(&new_pkt, sizeof(fc_pkt_t), 1, fout);
	if (n_written != 1) {
	    return 1;
	    break;
	}
    }

    return 0;
}
