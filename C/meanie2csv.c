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

/* Special-purpose packet viewer for helping analyze the "DAG" packets.
 * Lots of special-case stuff here; not generally useful.
 */

#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <net/ethernet.h>

#include <pcap/pcap.h>
#include <pcap/sll.h>

/*
Example commandline:

   dag-show input1.pcap input2.pcap ... inputN.pcap

The fields of each row are:

saddr,daddr,sport,dport,proto,timestamp,cksum,plen,pbytes,ttl,ipid

All the packets are presumed to be UDP, but we still print the source
(to be consistent with other tools).  The plen is the length, in bytes,
of the payload, and pbytes are the bytes of the payload, in hex.

ALL of the fields are expressed in hex EXCEPT for the timestamp, the
protocol, and the payload length.  The timestamp, protocol, and payload
length are in decimal.

*/

typedef struct {
    char **infile_names;
} dagshow_args_t;

typedef struct {
    int link_type;
    int header_len;
    pcap_t *pcap;
} handler_args_t;

static void
usage(char *const prog)
{
    /* FIXME make this non-lame */
    printf("usage: %s [-h] INPUT1 .. INPUTN\n",
	    prog);
    printf("    -h          Print help message and exit.\n");

    return;
}

static int
parse_args(
	int argc,
	char *const argv[], 
	dagshow_args_t *args)
{
    int opt;

    args->infile_names = NULL;

    while ((opt = getopt(argc, argv, "h")) != -1) {
	switch (opt) {
	    case 'h':
		usage(argv[0]);
		exit(0);
		break;
	    default:
		/* OOPS -- should not happen */
		return -1;
	}
    }

    if (argc > optind) {
	args->infile_names = (char **) argv + optind;
    }

    return 0;
}

static void
handler(
	unsigned char *user,
	const struct pcap_pkthdr *pkthdr,
	const unsigned char *packet)
{
    handler_args_t *args = (handler_args_t *) user;

    /*
     * Some packets are broken, and even if the caplen is long
     * enough for the IP and protocol headers, sometimes the packets
     * are just not that long.
     *
     * We're parsing an IPv4 packet, so it must have AT LEAST 20 bytes
     * after the link header has been removed to hold a header (without
     * any options).
     *
     * If the packet is too short, we just drop it.
     */

    if (pkthdr->caplen < (args->header_len + 20)) {
	return;
    }

    struct ip *ip_header = (struct ip *) (packet + args->header_len);

    /*
     * Now we know that we have at least the start of the ip_header.
     * Let's see whether we have enough for the whole header, and then
     * the 4 bytes that follow the IP header (because we need them
     * for sport and dport)
     *
     * If not, just drop it.
     */
    if (pkthdr->caplen < (args->header_len + (ip_header->ip_hl * 4) + 4)) {
	return;
    }

    uint8_t proto = ip_header->ip_p;
    if (proto != IPPROTO_UDP) {
	/* it's not a packet this tool can cope with;
	 * meanie packets are always UDP
	 */
	return;
    }

    uint32_t saddr = ntohl(ip_header->ip_src.s_addr);
    uint32_t daddr = ntohl(ip_header->ip_dst.s_addr);
    uint16_t len = ntohs(ip_header->ip_len);
    uint8_t ttl = ip_header->ip_ttl;
    uint16_t ipid = ntohs(ip_header->ip_id);

    uint16_t *proto_hdr = (uint16_t *)
            (((unsigned char *) ip_header) + (ip_header->ip_hl * 4));

    /*
     * It might be a meanie packet, but the packet is too short
     * (perhaps just a fragment): drop it.
     */
    if (pkthdr->caplen < (args->header_len + len)) {
	return;
    }

    uint16_t sport = ntohs(proto_hdr[0]);
    uint16_t dport = ntohs(proto_hdr[1]);
    uint16_t plen = ntohs(proto_hdr[2]) - 8;
    uint16_t cksum = ntohs(proto_hdr[3]);

    printf("%.8x,%.8x,%.4x,%.4x,%u,%ld.%.6ld,%.4x,%u,",
	    saddr, daddr, sport, dport, proto,
	    pkthdr->ts.tv_sec, pkthdr->ts.tv_usec, cksum, plen);

    uint8_t *base = (uint8_t *) (proto_hdr + 4);
    for (uint16_t i = 0; i < plen; i++) {
	printf("%.2x", base[i]);
    }
    printf(",%.2x,%.4x\n", ttl, ipid);

    return ;
}

static int
read_file(FILE *fin)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int header_len = 0;
    int result = 0;
    int rc;

    pcap_t *pcap = pcap_fopen_offline(fin, errbuf);
    if (pcap == NULL) {
	fprintf(stderr, "ERROR: [%s]\n", errbuf);
	return -1;
    }

    /*
     * Check that the DLT is one that we know how
     * to parse, and if so, find the link type header
     * length.  If we don't understand the data link
     * type, then we have to abandon this pcap.
     */
    int link_type = pcap_datalink(pcap);
    switch (link_type) {
	case DLT_EN10MB:
	    /* There's no mention in the code about how to handle
	     * a VLAN tag.  TODO: check that EN10MB can't have a
	     * VLAN tag (or stacked tags, for that matter)
	     */
	    header_len = sizeof(struct ether_header);
	    break;
	case DLT_RAW:
	    header_len = 0; /* TODO: double check */
	    break;
	case DLT_LINUX_SLL:
	    header_len = sizeof(struct sll_header);
	    break;
	default:
	    fprintf(stderr, "ERROR: unsupported capture type: %d\n",
		    link_type);
	    pcap_close(pcap);
	    return -1;
    }

    struct bpf_program filter;
    rc = pcap_compile(pcap, &filter, "ip and udp", 1, PCAP_NETMASK_UNKNOWN);
    if (rc != 0) {
	fprintf(stderr, "ERROR: filter failed\n");
	return -1;
    }
    rc = pcap_setfilter(pcap, &filter);
    if (rc != 0) {
	fprintf(stderr, "ERROR: setfilter failed\n");
	return -1;
    }

    handler_args_t handler_args = {
	link_type, header_len, pcap
    };

    if (pcap_loop(pcap, -1, handler, (u_char *) &handler_args) < 0) {
	/* TODO: if there's an error, can we get the errstr and print it? */
	fprintf(stderr, "ERROR: pcap_loop failed\n");
	result = -1;
    }

    pcap_close(pcap);
    pcap_freecode(&filter);

    return result;
}

static int
strendswith(
	const char *str,
	const char *suffix)
{
    size_t str_len = strlen(str);
    size_t suf_len = strlen(suffix);

    /* suffix is longer than the string; the string can't possibly
     * end with the suffix
     */
    if (suf_len > str_len) {
	return 0;
    }

    size_t off = str_len - suf_len;

    return strcmp(str + off, suffix) == 0;
}

static FILE *
do_popen(
	const char *fname,
	const char *app)
{

    if (access(fname, R_OK)) {
	fprintf(stderr, "ERROR: cannot read input [%s]\n", fname);
	return NULL;
    }

    char *buf = calloc(1, strlen(fname) + strlen(app) + 2);
    if (buf == NULL) {
	fprintf(stderr, "ERROR: calloc failed in do_open(%s, %s)\n",
		fname, app);
	return NULL;
    }

    sprintf(buf, "%s %s", app, fname);

    FILE *fin = popen(buf, "r");

    free(buf);

    return fin;
}

static int
read_file_by_name(char *fname)
{
    FILE *fin = NULL;
    int rc;

    /* FIXME: if it's a .gz, .bz2, .xz, or .lz4, then popen it
     * with the corresponding decoder (or whatever the right
     * way to get a FILE* for it happens to be)
     */

    if (strendswith(fname, ".gz")) {
	fin = do_popen(fname, "/bin/gunzip -c");
    }
    else if (strendswith(fname, ".lz4")) {
	fin = do_popen(fname, "/usr/bin/lz4cat");
    }
    else if (strendswith(fname, ".bz2")) {
	fin = do_popen(fname, "/bin/bunzip2 -c");
    }
    else if (strendswith(fname, ".xz")) {
	fin = do_popen(fname, "/usr/bin/lzcat");
    }
    else {
	fin = fopen(fname, "r");
    }

    if (fin == NULL) {
	fprintf(stderr, "ERROR: cannot open [%s]: %s\n",
		fname, strerror(errno));
	return -1;
    }

    rc = read_file(fin);

    /*
     * pcap_close closes the underlying FILE, so we don't
     * need to (and doing so will cause a double-free).
     */

    return rc;
}

int
main(
	int argc,
	char *const argv[])
{
    dagshow_args_t args;

    int rc = parse_args(argc, argv, &args);
    if (rc != 0) {
	return -1;
    }

    if (args.infile_names == NULL) {
	rc = read_file(stdin);
	return rc;
    }
    else {
	for (unsigned int i = 0; args.infile_names[i] != NULL; i++) {

	    char *fname = args.infile_names[i];
	    rc = read_file_by_name(args.infile_names[i]);
	    if (rc != 0) {
		fprintf(stderr, "%s: ERROR: could not read input [%s]\n",
			argv[0], fname);
		return -1;
	    }
	}

	return 0;
    }
}
