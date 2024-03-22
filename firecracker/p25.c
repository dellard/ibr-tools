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
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <pcap.h>

#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "firecracker.h"

typedef struct {
    pkt_chain_t *chain;
    fc_filter_t *filter;
} fc_pcap_handler_t;

static void
handler(
	unsigned char *user,
	const struct pcap_pkthdr *pkthdr,
	const unsigned char *packet)
{
    fc_pcap_handler_t *handler_args = (fc_pcap_handler_t *) user;
    pkt_chain_t *chain = handler_args->chain;
    fc_filter_t *filter = handler_args->filter;
    int rc;

    /* printf("chain %p %p\n", chain->first, chain->curr); */

    struct ether_header *eth_header = (struct ether_header *) packet;
    if (ntohs(eth_header->ether_type) != ETHERTYPE_IP) {
	// fprintf(stderr, "not IP %d\n", eth_header->ether_type);
	return;
    }

    struct ip *ip_header = (struct ip *) (packet + sizeof(struct ether_header));
    uint32_t saddr = ntohl(ip_header->ip_src.s_addr);
    uint32_t daddr = ntohl(ip_header->ip_dst.s_addr);
    uint8_t proto = ip_header->ip_p;
    uint16_t *proto_hdr = (uint16_t *)
	    (((unsigned char *) ip_header) + (ip_header->ip_hl * 4));
    uint16_t len = ntohs(ip_header->ip_len);

    /*
     * For protocols that don't have a source or destination port, we
     * pretend that they do, because these fields are often used for
     * similar purposes by other protocols
     */
    uint16_t sport = ntohs(proto_hdr[0]);
    uint16_t dport = ntohs(proto_hdr[1]);

    /*
     * Need to extract the other fields here, including the timestamp
     */

    rc = fc_extend_chain(chain);
    if (rc != 0) {
	pcap_free_chain(chain);
	fprintf(stderr, "ERROR: count not add another packet\n");
	exit(1);
    }

    uint32_t curr_cnt = chain->curr->cnt;
    fc_pkt_t *info = &chain->curr->pkts[curr_cnt];

    info->saddr = saddr;
    info->daddr = daddr;
    info->proto = proto;
    info->sport = sport;
    info->dport = dport;
    info->len = len;
    info->ts.ts_sec = pkthdr->ts.tv_sec;
    info->ts.ts_usec = pkthdr->ts.tv_usec;
    info->flags = 0; /* TODO */

    /* If there's a filter, and it doesn't match this packet,
     * then don't increment the current count.  Just ignore
     * this packet
     */
    if ((filter == NULL) || fc_filter_pkt(info, filter)) {
	chain->curr->cnt++;
    }
}

static int
pcap_reader(
	fc_fin_t *fin,
	pkt_chain_t *chain,
	fc_filter_t *filter)
{
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;

    pcap = pcap_fopen_offline(fin->file, err);
    if (pcap == NULL) {
	fprintf(stderr, "pcap_open failed [%s]\n", err);
	return 1;
    }

    fc_pcap_handler_t args;
    args.chain = chain;
    args.filter = filter;

    if (pcap_loop(pcap, 0, handler, (u_char *) &args) < 0) {
	/*
	 * don't consider this a fatal error, but let the
	 * user know something is amiss
	 */
	fprintf(stderr, "pcap_loop failed [%s]\n", pcap_geterr(pcap));
    }

    return 0;
}

int
fc_pcap_read(
	fc_fin_t *fin,
	pkt_chain_t *chain,
	fc_filter_t *filter)
{
    int rc;

    chain->first = NULL;
    chain->curr = NULL;

    rc = pcap_reader(fin, chain, filter);
    if (rc != 0) {
	fprintf(stderr, "ERROR: pcap reader failed\n");
	return -1;
    }

    return 0;
}
