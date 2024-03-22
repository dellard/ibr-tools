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

   show-frags [-f] [-t] INPUT1 [.. INPUTN]

The packets are extracted from the pcap files.  Note: pcapng is NOT
supported at this time.  If no pcap files are specified, input is read
from stdin.  If the name of a pcap file ends in .gz, .bz2, .xz, or .lz4,
the file is presumed to be in the corresponding compressed format, and
read directly (assuming that the corresponding utilities are installed).

If the -f flag is specified, then *only* information about fragments are
printed.  The default is to print info about all packets.

If the -t flag is specified, then the information about the payload is
omitted, and only the metadata is printed.

The output from show-frags is written to stdout as CSV, with one row per
IP packet in the input pcap files.  (non-IP packets are ignored)

The fields of each row are:

saddr,daddr,sport,dport,proto,timestamp,plen,ipid,morefrags,offset,payload

plen is the number of bytes in the fragment after the IP header.

The payload is included unless the -t flag is used.  If present, the
payload is represented as a hex string.

All values except the payload are representing in decimal.

For protocols that do not have sport and dport, the analogous values
are substituted if they exist (or zeros if the corresponding words
have no meaningful interpretation).  These are usually only meaningful
for TCP, UDP, SCTP and (somewhat) ICMP.
*/

typedef struct {
    int frags_only;
    int no_payload;
    char *infile_name;
    char *frag_pcap_fname;
} cmdline_args_t;

typedef struct {
    int link_type;
    int header_len;
    pcap_t *pcap;
    int frags_only;
    int no_payload;
    pcap_dumper_t *frag_dumper;
} handler_args_t;


static void
usage(char *const prog)
{
    /* FIXME make this non-lame */
    printf("usage: %s [-h] [-f] [-t] INFNAME\n", prog);
    printf("-h        Print help message and exit.\n");
    printf("-f        Only print fragments.  The default is to print all.\n");
    printf("-p FNAME  Save fragments, as a pcap file, in the given FNAME.\n");
    printf("-t        Do not print the payload bytes.\n");

    return;
}

static int
parse_args(
	int argc,
	char *const argv[], 
	cmdline_args_t *args)
{
    int opt;

    args->infile_name = NULL;
    args->frags_only = 0;
    args->no_payload = 0;
    args->frag_pcap_fname = NULL;

    while ((opt = getopt(argc, argv, "fhp:t")) != -1) {
	switch (opt) {
	    case 'f':
		args->frags_only = 1;
		break;
	    case 'h':
		usage(argv[0]);
		exit(0);
		break;
	    case 'p':
		args->frag_pcap_fname = optarg;
		break;
	    case 't':
		args->no_payload = 1;
		break;
	    default:
		/* OOPS -- should not happen */
		return -1;
	}
    }

    if (argc == optind + 1) {
	args->infile_name = (char *) argv[optind];
    }
    else if (argc == optind) {
	fprintf(stderr, "ERROR: %s: missing input pcap name\n", argv[0]);
	exit(1);
    }
    else {
	fprintf(stderr, "ERROR: %s: only one input file allowed\n", argv[0]);
	exit(1);
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
     * for sport and dport, or any kind of protocol-specific info)
     *
     * If not, just drop it.
     */
    if (pkthdr->caplen < (args->header_len + (ip_header->ip_hl * 4) + 4)) {
	return;
    }

    uint32_t saddr = ntohl(ip_header->ip_src.s_addr);
    uint32_t daddr = ntohl(ip_header->ip_dst.s_addr);

    uint8_t proto = ip_header->ip_p;
    uint16_t len = ntohs(ip_header->ip_len);

    uint16_t ipid = ntohs(ip_header->ip_id);
    uint16_t mfrag = (ntohs(ip_header->ip_off) & IP_MF) ? 1: 0;
    uint16_t offset = 8 * (ntohs(ip_header->ip_off) & IP_OFFMASK);

    if (args->frags_only) {
	if (!mfrag && !offset) {
	    return;
	}
    }

    uint8_t *ip_base = (uint8_t *) ip_header;
    uint16_t iph_len = ip_header->ip_hl * 4;
    uint16_t *proto_hdr = (uint16_t *) (ip_base + iph_len);

    uint16_t sport = 0;
    uint16_t dport = 0;

    /*
     * If the offset is zero, then it's the first packet (and maybe
     * the first and only) so look for the next-level protocol header.
     * If the offset is not zero, then don't even peek.
     *
     * FIXME if a packet is message is fragmented before the end of
     * the second-level protocol header, then we fail -- we can't
     * reassemble.
     */
    if (offset == 0) {
	/*
	 * For TCP, UDP or SCTP, we read the ports.  For other protocols,
	 * we interpret different values as "ports" where it makes sense
	 * (but in most cases, we don't do anything right now).
	 */
	if ((proto == 6) || (proto == 17) || (proto == 132)) {
	    /* this is a shortcut -- instead of checking whether the
	     * complete header is there, we only check whether the part
	     * of the header that we're going to read is actually there.
	     */
	    if (pkthdr->caplen <
		    (args->header_len + (ip_header->ip_hl * 4) + 4)) {
		return;
	    }

	    sport = ntohs(proto_hdr[0]);
	    dport = ntohs(proto_hdr[1]);
	}
	else if (proto == 1) {
	    /* like the shortcut described above -- this is a half-check */
	    if (pkthdr->caplen < (args->header_len + iph_len + 4)) {
		return;
	    }

	    /* This is somewhat backwards, but is bug-compatible with
	     * other tools.  TODO: should fix consistently everywhere.
	     */
	    sport = ((uint8_t *) proto_hdr)[0];
	    dport = ((uint8_t *) proto_hdr)[1];
	}
    }

    /* It's possible that the packet says that it's longer
     * than what got captured; don't just fly off the end
     */
    int plen = len - iph_len;
    if (plen < 0) {
	plen = -1;
    }

    printf("%u,%u,%u,%u,%u,%ld.%.6ld,%d,%u,%u,%u",
	    saddr, daddr, sport, dport, proto,
	    pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,
	    plen, ipid, mfrag, offset);

    if (!args->no_payload) {
	printf(",");

	uint8_t *payload = ip_base + iph_len;
	for (uint16_t i = 0; i < plen; i++) {
	    printf("%.2x", payload[i]);
	}
    }

    printf("\n");

    if (args->frag_dumper != NULL) {
	pcap_dump((u_char *) args->frag_dumper, pkthdr, packet);
    }

    return;
}

static int
read_file(
	FILE *fin,
	int frags_only,
	int no_payload,
	char *frag_pcap_fname)
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
    rc = pcap_compile(pcap, &filter, "ip", 1, PCAP_NETMASK_UNKNOWN);
    if (rc != 0) {
	fprintf(stderr, "ERROR: filter failed\n");
	return -1;
    }
    rc = pcap_setfilter(pcap, &filter);
    if (rc != 0) {
	fprintf(stderr, "ERROR: setfilter failed\n");
	return -1;
    }

    pcap_dumper_t *frag_dumper = NULL;
    if (frag_pcap_fname != NULL) {
	pcap_t *pd = pcap_open_dead(link_type, 65535);
	frag_dumper = pcap_dump_open(pd, frag_pcap_fname);
	if (frag_dumper == NULL) {
	    fprintf(stderr, "ERROR: [%s]\n", errbuf);
	    return -1;
	}
    }

    handler_args_t handler_args = {
	link_type, header_len, pcap, frags_only, no_payload,
	frag_dumper
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
read_file_by_name(
	char *fname,
	int frags_only,
	int no_payload,
	char *frag_pcap_fname)
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

    rc = read_file(fin, frags_only, no_payload, frag_pcap_fname);

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
    cmdline_args_t args;

    int rc = parse_args(argc, argv, &args);
    if (rc != 0) {
	return -1;
    }

    if (args.infile_name == NULL) {
	rc = read_file(stdin, args.frags_only, args.no_payload,
		args.frag_pcap_fname);
    }
    else {
	rc = read_file_by_name(args.infile_name,
		args.frags_only, args.no_payload, args.frag_pcap_fname);
	if (rc != 0) {
	    fprintf(stderr, "%s: ERROR: could not read input [%s]\n",
		    argv[0], args.infile_name);
	    return -1;
	}
    }

    return 0;
}
