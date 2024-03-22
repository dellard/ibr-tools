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
#include <time.h>
#include <unistd.h>
#include <pcap.h>

#include <netinet/ip.h>
#include <net/ethernet.h>

/*
Print CSV rows for each IPv4 packet in a pcap file.

saddr - the source address
daddr - the destination address
proto - the IP protocol number (TCP, UDP, ICMP, etc)
sport - the source port (or 0, if the protocol does not have sport)
dport - the destination port (or 0, if the protocol does not have dport)
p_chksum - the layer-4 checksum (the TCP, UDP, or ICMP checksum, NOT
        the IP header checksum)
iptotlen - length of the IP packet
ipid - the IP identifier
ttl - the TTL
ts_date - the packet timestamp as a string of the form "
        "YYYY-MM-DD HH:mm:ss.SS" i.e. "2020-02-12 18:01:01.720031"
ts_epoch - the packet timestamp, as a floating point number, measured
        from the epoch
findx - the index of the entry, in the file table, for the file from
        which this packet was read (always 0 for this app)
pindx - the index into the packet file of this packet
tcp_flags - the TCP flags (or 0, if not TCP)
tcp_seq - the TCP sequence number (or 0, if not TCP)
tcp_ack - the TCP acknowledgement number (or 0, if not TCP)
tcp_win - the TCP window size (or 0, if not TCP)
tcp_off - the offset to the TCP data segment (or 0, if not TCP)
ip_ihl - the IP header length
*/

typedef struct {
    struct timeval ts;	/* packet timestamp */
    uint32_t saddr;	/* destination address */
    uint32_t daddr;	/* destination address */
    uint16_t sport;	/* source port (or similar) */
    uint16_t dport;	/* destination port (or similar) */
    uint8_t proto;	/* IP proto */
    uint8_t flags; 	/* TCP flags (if applicable) */
    uint16_t len;	/* length of the original packet */
    int64_t findx;	/* file index -- always -1; not really used */
    uint64_t pindx;	/* packet index in pcap file */
    uint32_t tcp_seq;	/* tcp sequence number (or 0, if not TCP) */
    uint32_t tcp_ack;	/* tcp ack number (or 0, if not TCP) */
    uint32_t p_chksum;	/* the protocol checksum (not IP checksum) */
    uint16_t ipid;	/* IP ID value */
    uint16_t tcp_win;	/* TCP window size */
    uint16_t tcp_flags;	/* TCP flags */
    uint16_t tcp_off;	/* TCP offset */
    uint16_t ip_ihl;	/* IP header length (in 4-byte words) */
    uint8_t ttl;	/* IP TTL */
} pkt_info_t;


/*
 * Print the contents of a pkt_info_t to stdout
 */
static void
print_pkt_info(
	pkt_info_t *info,
	int compat)
{

    printf("%u,%u,%u,%u,%u,",
	    info->saddr, info->daddr, info->proto, info->sport, info->dport);
    printf("%u,%u,%u,%u,",
	    info->p_chksum, info->len, info->ipid, info->ttl);

    char secbuf[32];
    sprintf(secbuf, "%lu.%.06lu", info->ts.tv_sec, info->ts.tv_usec);

    char datebuf[32];
    strftime(datebuf, sizeof(datebuf), "%Y-%m-%d %H:%M:%S",
	    localtime(&info->ts.tv_sec));

    if (compat) {
	// Print timestamps in a way that is exactly compatible with
	// the way the python3-based dpkt library treats them.
	//
	// This is annoying and technically inaccurate, but necessary in
	// order to perfectly mimic the behavior of the Python3 pcap
	// module, which treats timestamps as a 64-bit float instead of
	// two ints (one for the seconds, and the other for the
	// microseconds).  This results in rounding errors that make it
	// appear as if the timestamps have nanosecond precision, but
	// this is nonsense.  However, in order to match bit-for-bit the
	// output of a Python3 program that uses dpkt pcap timestamps,
	// we need to use a bug-compatible way of expressing the
	// timestamps in text: first, express the timestamp (correctly)
	// in text, and second, convert the correct timestamp to a double,
	// and third, convert the double back to text, which introduces
	// rounding errors in the final digits.

	double realsec;
	sscanf(secbuf, "%lf", &realsec);

	// special case: if the fractional part of the timestamp is
	// zero, then don't print the decimal point or anything after
	//
	if (info->ts.tv_usec == 0) {
	    printf("%s,%.9lf,", datebuf, realsec);
	}
	else {
	    printf("%s.%.06lu,%.9lf,", datebuf, info->ts.tv_usec, realsec);
	}
    }
    else {
	printf("%s.%.06lu,%s,", datebuf, info->ts.tv_usec, secbuf);
    }

    printf("%ld,%lu,", info->findx, info->pindx);
    printf("%u,%u,%u,%u,%u,%u\n",
	    info->tcp_flags, info->tcp_seq, info->tcp_ack, info->tcp_win,
	    info->tcp_off, info->ip_ihl);

    return;
}

/*
 * Returns the offset, into the packet, of the end of the
 * datalink header (Ethernet header, or other header).
 *
 * For example, for an ordinary Ethernet frame, this will return
 * 14, and for RAW packets, it will return 0.
 *
 * If an unsupported frame is detected, or the frame cannot be
 * parsed to find its length, return -1.
 */
static int
dlt_offset(
	pcap_t *pcap,
	const struct pcap_pkthdr *pkthdr,
	const unsigned char *packet)
{
    uint32_t linktype = pcap_datalink(pcap);

    if (linktype == DLT_RAW) {
	return 0;
    }
    else if (linktype == DLT_EN10MB) {
	/*
	 * If we see a VLAN tag instead of the IP tag, then
	 * skip over it and continue, up to 4 tags deep.
	 * (we could go deeper, but that will only be needed
	 * in unusual circumstances, and I don't have a way
	 * to test deeper than 2 tags).  Anything ethertype
	 * other than VLAN or IP ethertype returns an error
	 */
	for (uint16_t i = 0; i < 4; i++) {
	    struct ether_header *eth_header =
		(struct ether_header *) (packet + (i * 4));
	    if (ntohs(eth_header->ether_type) == ETHERTYPE_IP) {
		return 14 + (i * 4);
	    }
	    else if (ntohs(eth_header->ether_type) != ETHERTYPE_VLAN) {
		return -1;
	    }
	}

	return -1;
    }
    else if (linktype == DLT_LINUX_SLL) {
	/* FIXME */
	return 16;
    }

    return -1;
}


// Macro to simplify checking whether an address
// we need to dereference is past the end of the packet.
//
// Only to be used inside the handler.
//
#define CHECK_ADDR(addr) \
{ if (((uint8_t *) (addr)) > (last_addr)) return; }

static void
handler(
	unsigned char *user,
	const struct pcap_pkthdr *pkthdr,
	const unsigned char *packet)
{
    static uint64_t pindx = 0;
    pcap_t *pcap = (pcap_t *) user;
    pkt_info_t info;

    /* Always increment this, even if it's a packet that we ignore,
     * because it's the index of the packet in the input file (NOT
     * the index in the output file)
     */
    info.pindx = pindx++;

    uint8_t *last_addr = (uint8_t *) packet + pkthdr->caplen;

    int header_len = dlt_offset(pcap, pkthdr, packet);
    if (header_len < 0) {
	/* If the header length is < 0, then it's a
	 * packet we don't know how to parse; drop it
	 */
	return;
    }

    struct ip *ip_header = (struct ip *) (packet + header_len);

    /* We don't parse fragments, except for the first
     */
    if ((ntohs(ip_header->ip_off) & 0x1fff) != 0) {
	return;
    }

    uint16_t ip_len = ntohs(ip_header->ip_len);

    /* If there's not even a valid, minimal IP header
     * (length 20), then something is totally messed up;
     * bail out
     */
    CHECK_ADDR((uint8_t *) &packet[header_len + 20]);

    uint32_t saddr = ntohl(ip_header->ip_src.s_addr);
    uint32_t daddr = ntohl(ip_header->ip_dst.s_addr);
    uint8_t proto = ip_header->ip_p;

    uint16_t ip_hdr_len = ip_header->ip_hl * 4;
    uint8_t *proto_u8 = (uint8_t *)
		(((unsigned char *) ip_header) + ip_hdr_len);
    uint16_t *proto_u16 = (uint16_t *) proto_u8;
    uint32_t *proto_u32 = (uint32_t *) proto_u8;

    info.ts.tv_sec = pkthdr->ts.tv_sec;
    info.ts.tv_usec = pkthdr->ts.tv_usec;

    info.ip_ihl = ip_header->ip_hl;
    info.len = ip_len;
    info.ipid = ntohs(ip_header->ip_id);
    info.ttl = ip_header->ip_ttl;
    info.proto = proto;

    info.saddr = saddr;
    info.daddr = daddr;
    info.findx = -1;

    info.sport = 0;
    info.dport = 0;
    info.p_chksum = 0;

    info.tcp_flags = 0;
    info.tcp_seq = 0;
    info.tcp_ack = 0;
    info.tcp_off = 0;
    info.tcp_win = 0;

    switch (proto) {
	case IPPROTO_TCP:
	    CHECK_ADDR((uint8_t *) &proto_u16[10]);
	    info.sport = ntohs(proto_u16[0]);
	    info.dport = ntohs(proto_u16[1]);
	    info.p_chksum = ntohs(proto_u16[8]);

	    /* this mask for the flags includes some reserved bits,
	     * but we DO see these bits set sometimes (they show
	     * up in RFCs for variants)
	     */
	    info.tcp_flags = ntohs(proto_u16[6]) & 0xff;
	    info.tcp_seq = ntohl(proto_u32[1]);
	    info.tcp_ack = ntohl(proto_u32[2]);
	    info.tcp_off = (ntohs(proto_u16[6]) >> 12) & 0xf;
	    info.tcp_win = ntohs(proto_u16[7]);
	    break;
	case IPPROTO_UDP:
	    CHECK_ADDR((uint8_t *) &proto_u16[4]);
	    info.sport = ntohs(proto_u16[0]);
	    info.dport = ntohs(proto_u16[1]);
	    info.p_chksum = ntohs(proto_u16[3]);
	    break;
	case IPPROTO_ICMP:
	    CHECK_ADDR((uint8_t *) &proto_u16[2]);
	    info.sport = proto_u8[0];
	    info.dport = proto_u8[1];
	    info.p_chksum = ntohs(proto_u16[1]);
	    break;
	case IPPROTO_SCTP:
	    CHECK_ADDR((uint8_t *) &proto_u16[2]);
	    info.sport = ntohs(proto_u16[0]);
	    info.dport = ntohs(proto_u16[1]);
	    info.p_chksum = ntohl(proto_u32[2]);
	    break;
	case IPPROTO_GRE:
	    CHECK_ADDR((uint8_t *) &proto_u16[2]);

	    /* the checksum is optional; we ignore it
	     * (to be backward compatible with the
	     * previous pcap parser)
	     */
	    info.p_chksum = 0;
	    break;
	case IPPROTO_IPV6:
	    /* FIXME wrong, but we don't look deeper */
	    CHECK_ADDR((uint8_t *) &proto_u16[1]);

	    info.p_chksum = ntohs(ip_header->ip_sum);
	    break;
	default:
	    break;
    }

    int compat = 0;

#ifdef PCAP2CSV_COMPAT
    compat = 1;
#endif /* PCAP2CSV_COMPAT */

    print_pkt_info(&info, compat);
}

static int
pcap_reader(FILE *fin)
{
    char err[PCAP_ERRBUF_SIZE];
    pcap_t *pcap;

    pcap = pcap_fopen_offline(fin, err);
    if (pcap == NULL) {
	fprintf(stderr, "pcap_open failed [%s]\n", err);
	return 1;
    }

    switch (pcap_datalink(pcap)) {
	case DLT_RAW:
	case DLT_EN10MB:
	case DLT_LINUX_SLL:
	    break;
	default:
	    fprintf(stderr, "ERROR: unsupported link type (%d)\n",
		    pcap_datalink(pcap));
	    exit(1);
    }

    if (pcap_loop(pcap, 0, handler, (u_char *) pcap) < 0) {
	/*
	 * don't consider this a fatal error, but let the
	 * user know something is amiss
	 */
	fprintf(stderr, "pcap_loop failed [%s]\n", pcap_geterr(pcap));
    }

    return 0;
}

static void
usage(
	char *progname)
{

    printf("usage: %s [-h]\n", progname);
    printf("\n"
"Commandline flags:\n"
"-h      Print usage message and exit.\n"
"\n"
"For backward compatibility, the option [-f N] is\n"
"permitted, but ignored.\n"
"\n"
"Reads a pcap from stdin and writes a CSV description\n"
"of each IPv4 packet to stdout.\n"
"\n"
"The fields in the CSV output represent:\n"
"\n"
"saddr - the source address\n"
"daddr - the destination address\n"
"proto - the IP protocol number (TCP, UDP, ICMP, etc)\n"
"sport - the source port (or 0, if the protocol does not have sport)\n"
"dport - the destination port (or 0, if the protocol does not have dport)\n"
"p_chksum - the layer-4 checksum (the TCP, UDP, or ICMP checksum, NOT\n"
"        the IP header checksum)\n"
"iptotlen - length of the IP packet\n"
"ipid - the IP identifier\n"
"ttl - the TTL\n"
"ts_date - the packet timestamp as a string of the form\n"
"        \"YYYY-MM-DD HH:mm:ss.SS\" i.e. \"2020-02-12 18:01:01.720031\"\n"
"ts_epoch - the packet timestamp, as a floating point number, measured\n"
"        from the epoch\n"
"findx - the index of the entry, in the file table, for the file from\n"
"        which this packet was read (always -1 for this app)\n"
"pindx - the index into the packet file of this packet.  Note that this\n"
"        value is meaningless if the CSV has been merged with other files\n"
"        and/or the original provence is lost.\n"
"tcp_flags - the TCP flags (or 0, if not TCP)\n"
"tcp_seq - the TCP sequence number (or 0, if not TCP)\n"
"tcp_ack - the TCP acknowledgement number (or 0, if not TCP)\n"
"tcp_win - the TCP window size (or 0, if not TCP)\n"
"tcp_off - the offset to the TCP data segment (or 0, if not TCP)\n"
"ip_ihl - the IP header length\n"
"\n"
"All numbers are expressed in decimal.\n");

}


int
main(
	int argc,
	char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, "f:h")) != -1) {
	switch (opt) {
	    case 'h':
		usage(argv[0]);
		exit(0);
		break;
	    case 'f':
		/*
		 * NOTE: the findx option is permitted, to make
		 * this compatible with the old pcap2csv, but
		 * the value is IGNORED
		 */
		break;
	    default:
		usage(argv[0]);
		exit(1);
	}
    }

    /*
     * extra commandline parameters are IGNORED
     * (and are not considered an error, to be
     * backward compatible with the old pcap2csv
     */

    int rc = pcap_reader(stdin);

    exit(rc);
}
