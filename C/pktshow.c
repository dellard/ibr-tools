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


   pktshow -f TTL input1.pcap input2.pcap ... inputN.pcap

The -f parameter lets the user pick a field to extract from the packets.
The default field is TTL; the if no -f parameter is provided, the TTL is
extracted.  The permitted field names are "TTL", "IPID", "OFF" (fragment
offset), and "HLEN" (for IP header length, in 32-bit words).

The packets are extracted from the pcap files.  Note: pcapng is NOT
supported at this time.  If no pcap files are specified, input is read
from stdin.  If the name of a pcap file ends in .gz, .bz2, .xz, or .lz4,
the file is presumed to be in the corresponding compressed format, and
read directly (assuming that the corresponding utilities are installed).

The output from pktshow is written to stdout as CSV, with one row per
IP packet in the input pcap files.  (non-IP packets are ignored)

The fields of each row are:

saddr,daddr,sport,dport,proto,timestamp,len,value,valuename

For protocols that do not have sport and dport, the analogous values
are substituted if they exist (or zeros if the corresponding words
have no meaningful interpretation).

The value is the additional field extracted from each packet, and the
valuename is the "name" of that field.
*/

typedef enum {
    PKTSHOW_FIELD_TTL,
    PKTSHOW_FIELD_IPID,
    PKTSHOW_FIELD_IPOFF,
    PKTSHOW_FIELD_HLEN,
} pktshow_field_code_t;

typedef struct {
    char *field_name;
    char *bpf;
    pktshow_field_code_t field_code;
    char **infile_names;
} pktshow_args_t;

typedef struct {
    int link_type;
    int header_len;
    pktshow_field_code_t field_code;
    pcap_t *pcap;
} handler_args_t;


static void
usage(char *const prog)
{
    /* FIXME make this non-lame */
    printf("usage: %s [-h] [-f FIELD] INPUT1 .. INPUTN\n",
	    prog);
    printf("    -h          Print help message and exit.\n");
    printf("    -b FILTER   BPF filter for the packets.\n");
    printf("    -f FIELD    Extract the given field.  The default is TTL.\n");

    return;
}

static int
parse_args(
	int argc,
	char *const argv[], 
	pktshow_args_t *args)
{
    int opt;

    args->field_name = "TTL";
    args->bpf = NULL;
    args->field_code = PKTSHOW_FIELD_TTL;
    args->infile_names = NULL;

    while ((opt = getopt(argc, argv, "b:f:h")) != -1) {
	switch (opt) {
	    case 'b':
		args->bpf = optarg;
		break;
	    case 'f':
		args->field_name = optarg;
		break;
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

    if (!strcmp(args->field_name, "TTL")) {
	args->field_code = PKTSHOW_FIELD_TTL;
    }
    else if (!strcmp(args->field_name, "IPID")) {
	args->field_code = PKTSHOW_FIELD_IPID;
    }
    else if (!strcmp(args->field_name, "OFF")) {
	args->field_code = PKTSHOW_FIELD_IPOFF;
    }
    else if (!strcmp(args->field_name, "HLEN")) {
	args->field_code = PKTSHOW_FIELD_HLEN;
    }
    else {
	fprintf(stderr, "ERROR: unknown field name [%s]\n",
		args->field_name);
	return -1;
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
	/* printf("cap %d too short 2 %d %d %d\n",
		ip_header->ip_p, pkthdr->caplen,
		ip_header->ip_hl, ip_header->ip_p); */
	return;
    }

    uint32_t saddr = ntohl(ip_header->ip_src.s_addr);
    uint32_t daddr = ntohl(ip_header->ip_dst.s_addr);
    uint8_t proto = ip_header->ip_p;
    uint16_t len = ntohs(ip_header->ip_len);

    uint16_t *proto_hdr = (uint16_t *)
            (((unsigned char *) ip_header) + (ip_header->ip_hl * 4));

    /*
     * For TCP, UDP or SCTP, we read the ports.  For other protocols,
     * we interpret different values as "ports" where it makes sense
     * (but in most cases, we don't do anything right now).
     */
    uint16_t sport = 0;
    uint16_t dport = 0;
    if ((proto == 6) || (proto == 17) || (proto == 132)) {
	/* this is a shortcut -- instead of checking whether the
	 * complete header is there, we only check whether the part
	 * of the header that we're going to read is actually there.
	 */
	if (pkthdr->caplen < (args->header_len + (ip_header->ip_hl * 4) + 4)) {
	    return;
	}

	sport = ntohs(proto_hdr[0]);
	dport = ntohs(proto_hdr[1]);
    }
    else if (proto == 1) {
	/* like the shortcut described above -- this is a half-check */
	if (pkthdr->caplen < (args->header_len + (ip_header->ip_hl * 4) + 2)) {
	    return;
	}

	/* This is somewhat backwards, but is bug-compatible with
	 * other tools.  TODO: should fix consistently everywhere.
	 */
	sport = ((uint8_t *) proto_hdr)[0];
	dport = ((uint8_t *) proto_hdr)[1];
    }

    uint32_t val = 0;
    char *val_name = "??";

    switch (args->field_code) {
	case PKTSHOW_FIELD_TTL:
	    val = ip_header->ip_ttl; 
	    val_name = "TTL";
	    break;
	case PKTSHOW_FIELD_IPID:
	    val = ntohs(ip_header->ip_id); 
	    val_name = "IPID";
	    break;
	case PKTSHOW_FIELD_IPOFF:
	    val = 0x1fff & ntohs(ip_header->ip_off);
	    val_name = "OFF";
	    break;
	case PKTSHOW_FIELD_HLEN:
	    val = ip_header->ip_hl;
	    val_name = "HLEN";
	    break;
	default:
	    /* should never happen, should have been caught already */
	    fprintf(stderr, "ERROR: unexpected field code [%d]\n", 
		    args->field_code);
	    pcap_breakloop(args->pcap);
	    break;
    }

    printf("%u,%u,%u,%u,%u,%ld.%.6ld,%u,%u,%s\n",
	    saddr, daddr, sport, dport, proto,
	    pkthdr->ts.tv_sec, pkthdr->ts.tv_usec,
	    len, val, val_name);

    return;
}

static int
read_file(
	FILE *fin,
	pktshow_field_code_t field_code,
	char *bpf)
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

    char *filter_str;
    if (bpf == NULL) {
	filter_str = "ip";
    }
    else {
	/* We need to escape the "ip" because it's a reserved word
	 * in BPF, as well as being an argument here.  Ugh.
	 */
	char *base_predicate = "ether proto \\ip and ";

	/* Enough space to insert the base_predicate at the start,
	 * because we always constrain the input to ip (right now)
	 */
	filter_str = malloc(strlen(base_predicate) + strlen(bpf));
	if (filter_str == NULL) {
	    fprintf(stderr, "ERROR: malloc failed\n");
	    pcap_close(pcap);
	    return -1;
	}

	sprintf(filter_str, "%s%s", base_predicate, bpf);
    }

    struct bpf_program filter;
    rc = pcap_compile(pcap, &filter, filter_str, 1, PCAP_NETMASK_UNKNOWN);
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
	link_type, header_len, field_code, pcap
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
	pktshow_field_code_t field_code,
	char *bpf)
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

    rc = read_file(fin, field_code, bpf);

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
    pktshow_args_t args;

    int rc = parse_args(argc, argv, &args);
    if (rc != 0) {
	return -1;
    }

    if (args.infile_names == NULL) {
	rc = read_file(stdin, args.field_code, args.bpf);
    }
    else {
	for (unsigned int i = 0; args.infile_names[i] != NULL; i++) {

	    char *fname = args.infile_names[i];
	    rc = read_file_by_name(
		    args.infile_names[i], args.field_code, args.bpf);
	    if (rc != 0) {
		fprintf(stderr, "%s: ERROR: could not read input [%s]\n",
			argv[0], fname);
		return -1;
	    }
	}
    }

    return 0;
}
