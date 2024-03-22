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

#define MAX_LINE_LEN	(2048)

int
fc_csv_read(
	fc_fin_t *fin,
	pkt_chain_t *chain,
	fc_filter_t *filter)
{
    char buf[MAX_LINE_LEN];
    int rc;

    chain->first = NULL;
    chain->curr = NULL;

    memset(buf, 0, MAX_LINE_LEN);

    for (;;) {
	char *p = fgets(buf, MAX_LINE_LEN, fin->file);
	if (p == NULL) {
	    break;
	}

	uint32_t saddr, daddr, proto, sport, dport, dummy, len;
	uint32_t ts_sec, ts_usec;

	/* This reproduces the functionality of the sscanf call above,
	 * but is much, much faster...  and has no error checking
	 * WHATSOEVER.
	 */
	/*
	 * The following bit of hideous code replaces the following:

	    rc = sscanf(p, "%u,%u,%u,%u,%u,%u,%u",
		    &saddr, &daddr, &proto, &sport, &dport, &dummy, &len);

	 * but runs much, much faster.  When we use sscanf, this single
	 * line consumes about half the runtime of the entire program
	 * (for reading uncompressed data -- if the data is compressed,
	 * then uncompressing the data is even more expensive).
	 *
	 * We sacrifice some error checking and readability to make this
	 * run fast, since speed is the first priority for firecracker.
	 */

	{
	    char *endptr;

	    saddr = (uint32_t) strtoll(p, &endptr, 10);
	    if (*endptr != ',') {
		printf("end %s\n", endptr);
		return -1;
	    }
	    daddr = (uint32_t) strtoll(endptr + 1, &endptr, 10);
	    if (*endptr != ',') {
		return -2;
	    }
	    proto = (uint32_t) strtoll(endptr + 1, &endptr, 10);
	    if (*endptr != ',') {
		return -3;
	    }
	    sport = (uint32_t) strtoll(endptr + 1, &endptr, 10);
	    if (*endptr != ',') {
		return -4;
	    }
	    dport = (uint32_t) strtoll(endptr + 1, &endptr, 10);
	    if (*endptr != ',') {
		return -5;
	    }
	    dummy = (uint32_t) strtoll(endptr + 1, &endptr, 10);
	    (void) dummy; /* prevent gcc warnings re unused variable */
	    if (*endptr != ',') {
		return -6;
	    }
	    len = (uint32_t) strtoll(endptr + 1, &endptr, 10);
	    if (*endptr != ',') {
		return -7;
	    }

	    for (int i = 0; i < 3; i++) {
		endptr = strchr(endptr + 1, ',');
		if (*endptr != ',') {
		    return -8;
		}
	    }
	    ts_sec = (uint32_t) strtoll(endptr + 1, &endptr, 10);
	    if (*endptr != '.') {
		return -9;
	    }
	    ts_usec = 1000000 * strtod(endptr, &endptr);

	    /* It is OK if there are more fields after ts_use, or it's
	     * the last fields on the line (followed by a newline).  The
	     * first matches the output from pcap2csv looks, while the
	     * second matches the output from zeek2csv
	     */
	    if ((*endptr != ',') && (*endptr != '\n')) {
		return -10;
	    }

	}

	rc = fc_extend_chain(chain);
	if (rc != 0) {
	    pcap_free_chain(chain);
	    return 1;
	}

	uint32_t curr_cnt = chain->curr->cnt;
	fc_pkt_t *pkt = &chain->curr->pkts[curr_cnt];

	pkt->saddr = saddr;
	pkt->daddr = daddr;
	pkt->proto = (uint8_t) proto;
	pkt->sport = (uint16_t) sport;
	pkt->dport = (uint16_t) dport;
	pkt->len = (uint16_t) len;
	pkt->ts.ts_sec = ts_sec;
	pkt->ts.ts_usec = ts_usec;
	pkt->flags = 0; /* TODO */

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
