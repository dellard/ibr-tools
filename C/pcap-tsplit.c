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

#include <errno.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <pcap/pcap.h>

/*
Example commandline:

    pcap-tsplit -s X,Y,foo.pcap [-s Y,Z,bar.pcap] [-f BPF] \
	    input1.pcap input2.pcap ... inputN.pcap

The (optional) -f parameter is a BPF predicate; any packets
that don't satisfy this predicate are discarded.

Each -s "span" parameter is a comma-separated triple STARTTS,ENDTS,FNAME
where STARTTS and ENDTS are timestamps, relative to the unix epoch, and
FNAME is a pcap file.  If the timestamp of a packet is strictly greater
or equal to STARTTS and less than ENDTS, it is written to FNAME.  Note
that FNAME is created as an empty pcap file (of the same type as the
input pcap) when the program is run.  The FNAME of each span should be
unique, but this is not checked.  A maximum of 128 spans can be
specified.  If no spans are specified, then the program exits
immediately after creating the output files.

Note that spans may overlap; the timestamp of a packet might fall into
multiple spans.  In this case, it will be written to all of the
corresponding output FNAMEs.

*/

#define MAX_SPANS	(128)

typedef struct {
    struct timeval start_ts;
    struct timeval end_ts;
    char *fname;
    pcap_dumper_t *output;
} tsplit_span_t;

typedef struct {
    char *bpf;
    tsplit_span_t spans[MAX_SPANS];
    char **infile_names;
} tsplit_args_t;

typedef struct {
    pcap_t *in_pcap;
    tsplit_span_t *spans;
} handler_args_t;


static void
usage(char *const prog)
{
    /* FIXME make this non-lame */
    printf("usage: %s [-h] -s STS1,ETS1,FOUT1 [-s STS2,ETS2,FOUT2 ...] \\\n",
	    prog);
    printf("        FIN1 .. FINN\n");

    return;
}

static int
parse_args(
	int argc,
	char *const argv[],
	tsplit_args_t *args)
{
    int opt;
    int span_cnt = 0;

    char *span_descriptions[MAX_SPANS];
    for (unsigned int i = 0; i < MAX_SPANS; i++) {
	span_descriptions[i] = NULL;
    }

    for (unsigned int i = 0; i < MAX_SPANS; i++) {
	args->spans[i].fname = NULL;
	args->spans[i].output = NULL;
    }

    while ((opt = getopt(argc, argv, "f:hs:")) != -1) {
	switch (opt) {
	    case 'f':
		args->bpf = optarg;
		break;
	    case 'h':
		usage(argv[0]);
		exit(0);
		break;
	    case 's':
		if (span_cnt >= MAX_SPANS) {
		    fprintf(stderr, "ERROR: %s: too many spans (> %d)\n",
			    argv[0], MAX_SPANS);
		    exit(1);
		}
		span_descriptions[span_cnt++] = optarg;
		break;
	    default:
		/* OOPS -- should not happen */
		return -1;
	}
    }

    if (argc > optind) {
	args->infile_names = (char **) argv + optind;
    }

    for (unsigned int i = 0; i < span_cnt; i++) {
	/* make these much longer than necessary, so we don't
	 * need to worry about overrunning them in any plausible
	 * scenario
	 */
	char start_usec_str[32 + 1];
	char end_usec_str[32 + 1];

	tsplit_span_t *span = &(args->spans[i]);

	/* max_len is always longer than strictly necessary, since any
	 * substring will be shorter than the entire string...  but it's
	 * easier than computing the precise number of bytes required
	 */
	size_t max_len = strlen(span_descriptions[i]) + 1;
	span->fname = malloc(max_len);

	int rc = sscanf(span_descriptions[i],
		"%ld.%32[0-9],%ld.%32[0-9],%s",
		&(span->start_ts.tv_sec), start_usec_str,
		&(span->end_ts.tv_sec), end_usec_str,
		span->fname);
	if (rc != 5) {
	    fprintf(stderr, "ERROR: bad span spec [%s]\n",
		    span_descriptions[i]);
	    return -1;
	}

	/* if the usec strings are shorter than 6, then
	 * right-pad them with zeros, because these must be in
	 * units of microseconds (i.e. "2" must be changed to
	 * "200000" because 0.2 seconds is 200000 microseconds).
	 */

	for (unsigned int i = strlen(start_usec_str); i < 6; i++) {
	    start_usec_str[i] = '0';
	    start_usec_str[i + 1] = 0;
	}
	for (unsigned int i = strlen(end_usec_str); i < 6; i++) {
	    end_usec_str[i] = '0';
	    end_usec_str[i + 1] = 0;
	}

	/* And if the usec strings are longer than 6, then just
	 * truncate them.
	 * TODO: it might be better to round them instead of
	 * blindly truncating them
	 */
	start_usec_str[6] = 0;
	end_usec_str[6] = 0;

	span->start_ts.tv_usec = atoi(start_usec_str);
	span->end_ts.tv_usec = atoi(end_usec_str);

	args->spans[i].output = NULL;
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

    for (unsigned int i = 0; i < MAX_SPANS; i++) {
	tsplit_span_t *span = &(args->spans[i]);
	if (span->output == NULL) {
	    break;
	}

	if (timercmp(&pkthdr->ts, &span->start_ts, >=) &&
		timercmp(&pkthdr->ts, &span->end_ts, <)) {
	    pcap_dump((u_char *) span->output, pkthdr, packet);
	}
    }

    return;
}

static int
read_file(
	FILE *fin,
	tsplit_args_t *args)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    int result = 0;
    int rc;

    pcap_t *pcap = pcap_fopen_offline(fin, errbuf);
    if (pcap == NULL) {
	fprintf(stderr, "ERROR: [%s]\n", errbuf);
	return -1;
    }

    int link_type = pcap_datalink(pcap);

    /*
     * If we haven't already opened the output pcaps, then do
     * so now.  We delay opening the output until after we've
     * opened the input, so we can use the same DLT for the ouput
     * and the input (we always use the same output DLT as the
     * FIRST input stream -- even though different input streams
     * might use different DLTs)
     */
    for (unsigned int i = 0; i < MAX_SPANS; i++) {
	if (args->spans[i].fname == NULL) {
	    break;
	}
	pcap_t *pcap_out = pcap_open_dead(link_type, 65536);
	pcap_dumper_t *dumper = pcap_dump_open(
		pcap_out, args->spans[i].fname);
	if (dumper == NULL) {
	    return -1;
	}

	args->spans[i].output = dumper;
    }

    /* TODO: see if we can compile this once and then use it for
     * multiple input pcaps, or whether we really do need to compile
     * a new one for each pcap.  (unless the filter is very complex,
     * or the input pcaps are very short, then it's probably not much
     * overhead to recompile it for each, but it would be nice to know)
     */

    struct bpf_program filter;
    if (args->bpf != NULL) {
	rc = pcap_compile(pcap, &filter, args->bpf, 1, PCAP_NETMASK_UNKNOWN);
	if (rc != 0) {
	    fprintf(stderr, "ERROR: filter failed\n");
	    return -1;
	}
	rc = pcap_setfilter(pcap, &filter);
	if (rc != 0) {
	    fprintf(stderr, "ERROR: setfilter failed\n");
	    return -1;
	}
    }

    handler_args_t handler_args = {
	pcap, args->spans
    };

    if (pcap_loop(pcap, -1, handler, (u_char *) &handler_args) < 0) {
	/* TODO: if there's an error, can we get the errstr and print it? */
	fprintf(stderr, "ERROR: pcap_loop failed\n");
	result = -1;
    }

    pcap_close(pcap);

    if (args->bpf != NULL) {
	pcap_freecode(&filter);
    }

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
	tsplit_args_t *args)
{
    FILE *fin = NULL;
    int rc;

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

    rc = read_file(fin, args);

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
    tsplit_args_t args;

    int rc = parse_args(argc, argv, &args);
    if (rc != 0) {
	return -1;
    }

    if (args.infile_names == NULL) {
	rc = read_file(stdin, &args);
    }
    else {
	for (unsigned int i = 0; args.infile_names[i] != NULL; i++) {

	    char *fname = args.infile_names[i];
	    rc = read_file_by_name(args.infile_names[i], &args);
	    if (rc != 0) {
		fprintf(stderr, "%s: ERROR: could not read input [%s]\n",
			argv[0], fname);
		rc = -1;
		break;
	    }
	}
    }

    for (unsigned int i = 0; i < MAX_SPANS; i++) {
	if (args.spans[i].fname == NULL) {
	    break;
	}
	pcap_dump_close(args.spans[i].output);
    }

    return rc;
}
