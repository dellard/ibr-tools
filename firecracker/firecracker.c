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
#include <unistd.h>

#include "firecracker.h"

/*
Example commandline:

   firecracker -t S -t PA -t PAD24 -o foo input.pcap

The -o parameter provides the prefix of the name for the output file to
create.

The -t parameters are the queries to evaluate.  The queries begin with
the fields on which to do the counting, in the order of the grouping.
The following fields are defined:

    S - the source address
    D - the destination address
    E - the ephemeral (source) port
    A - the application (destination) port
    P - the IP protocol

If the S or D are followed by a prefix length, then only the prefix of
the corresponding length is used.  For example, S24 means that the
source addresses should be masked so that only the first 24 bits are
used.  The default is to use all of the bits.  (Firecracker only
supports IPv4, so this is 32 bits.)

By default, the output from firecracker is a single CSV file.  The first
field (or the second, if the -T parameter is given) of the file is count
of the records that match the rest of the line.

The "/" operator is used to group the output into different files,
according to the fields given after the "/".  For example, the query
"D/D24" will create an output file for each destination /24 subnet, and
each file will contain the packet count for each destination address
observed in that /24.  (lines with zero counts are not written to the
output files)

This example read input.pcap, and create several table files:

1. For "-t S", a table of counts by source address, named foo-S.csv

2. For "-t PA", a table of counts by protocol and app port, named
    foo-PA.csv

3. For "-t PA/D24", a table of counts by protocol and app port, divided
    by destination /24, named foo-PAD-x.csv, foo-PAD-y.csv, etc.  where
    x and y are the destination /24 prefixes observed in the input.

*/

#define MAX_INPUT_FILES	(7 * 24)
#define MAX_QUERIES (25)

typedef struct {
    char **input_fnames;
    int show_max;
    fc_query_t queries[MAX_QUERIES];
    int n_queries;
    fc_filter_t filter;
    int interval;
    char *output_fname;
    char *tag;
    int show_query;
    int alignment;
    char *stdin_type;
    int normalized;
} firecracker_args_t;


static void
usage(char *const prog)
{
    /* FIXME make this non-lame */
    /* FIXME this is incomplete */
    printf("usage: %s [-h] [-F filter] [-t query] input1 .. inputN\n",
	    prog);
    printf("    -h          Print help message and exit.\n");
    printf("    -A N        Align timing intervals on N-second boundaries.\n");
    printf("    -F FILTER   Apply FILTER to the data prior to the query\n");
    printf("    -I N        Group the output by N seconds.  The default\n");
    printf("                value of N is 900.\n");
    printf("    -m N        Only show the top N values for each group,\n");
    printf("                instead of showing all of them.\n");
    printf("    -n          Print the normalized counts (as a fraction of the total)\n");
    printf("                in addition to the raw counts.\n");
    printf("    -o FNAME    Write output to the given FNAME instead of stdout.\n");
    printf("    -s type     If reading from stdin, specify the input type,\n");
    printf("                which must be one of csv, pcap, or fc5.  The\n");
    printf("                default is csv.\n");
    printf("    -t QUERY    Specify the query and grouping to use.\n");
    printf("                The default QUERY is \"PA\".\n");
    printf("    -T          Add the query to the end of each count line.\n");

    return;
}

static int
parse_args(
	int argc,
	char *const argv[], 
	firecracker_args_t *args)
{
    int opt;
    char *filter_str = NULL;
    char *query_strs[MAX_QUERIES];
    int rc;

    args->show_max = -1;
    args->n_queries = 0;
    args->filter.n_fields = 0;
    args->interval = 900;
    args->show_query = 0;
    args->alignment = 0;
    args->stdin_type = "csv";
    args->normalized = 0;
    args->output_fname = NULL;

    for (int i = 0; i < MAX_QUERIES; i++) {
	args->queries[i].n_fields = 0;
    }

    while ((opt = getopt(argc, argv, "A:hF:I:m:no:s:t:T")) != -1) {
	switch (opt) {
	    case 'A':
		args->alignment = strtol(optarg, NULL, 10);
		if (args->alignment < 0) {
		    fprintf(stderr, "%s: ERROR: alignment must be >= 0\n",
			    argv[0]);
		    return -1;
		}
		break;
	    case 'h':
		usage(argv[0]);
		exit(0);
		break;
	    case 'F':
		filter_str = optarg;
		break;
	    case 'I':
		args->interval = strtol(optarg, NULL, 10);
		if (args->interval < 1) {
		    fprintf(stderr, "%s: ERROR: interval must be > 0\n",
			    argv[0]);
		    return -1;
		}
		break;
	    case 'm':
		args->show_max = atol(optarg);
		if (args->show_max < 0) {
		    fprintf(stderr, "%s: ERROR: max-N must be >= 0\n",
			    argv[0]);
		    return -1;
		}
		break;
	    case 'n':
		args->normalized = 1;
		break;
	    case 't':
		query_strs[args->n_queries++] = optarg;
		break;
	    case 'T':
		args->show_query = 1;
		break;
	    case 's':
		args->stdin_type = optarg;
		break;
	    case 'o':
		args->output_fname = optarg;
		break;
	    default:
		/* OOPS -- should not happen */
		return -1;
	}
    }

    if (args->n_queries == 0) {
	query_strs[0] = "PA";
	args->n_queries = 1;
    }

    /*
     * If there are multiple queries, then *always* show the
     * query for each line of the output
     */
    if (args->n_queries > 1) {
	args->show_query = 1;
    }

    for (int i = 0; i < args->n_queries; i++) {
	rc = fc_str2query(query_strs[i], &args->queries[i]);
	if (rc != 0) {
	    fprintf(stderr, "%s: ERROR: bad query spec [%s]\n",
		    argv[0], query_strs[i]);
	    return -1;
	}
	args->queries[i].show_max = args->show_max;
	args->queries[i].query_str = query_strs[i];
	args->queries[i].show_query = args->show_query;
    }

    if (filter_str != NULL) {
	rc = fc_str2filter(filter_str, &args->filter);
	if (rc != 0) {
	    fprintf(stderr, "%s: ERROR: bad filter spec [%s]\n",
		    argv[0], filter_str);
	    return -1;
	}
    }

    args->input_fnames = (char **) argv + optind;

    return 0;
}

int
main(
	int argc,
	char *const argv[])
{
    firecracker_args_t fc_args;
    uint32_t i;
    uint32_t n_chains;

    int rc = parse_args(argc, argv, &fc_args);
    if (rc != 0) {
	return -1;
    }

    pkt_chain_t chains[MAX_INPUT_FILES];
    fc_chunk_t chunk;

    if (fc_args.input_fnames[0] == NULL) {
	rc = fc_read_stdin(fc_args.stdin_type, &chains[0], &fc_args.filter);
	if (rc != 0) {
	    fprintf(stderr, "%s: ERROR: could not read stdin\n", argv[0]);
	    return -1;
	}
	n_chains = 1;
    }
    else {
	for (i = 0; fc_args.input_fnames[i] != NULL; i++) {

	    if (i >= MAX_INPUT_FILES) {
		fprintf(stderr, "%s: ERROR: too many input files (max=%d)\n",
			argv[0], MAX_INPUT_FILES);
		return -1;
	    }

	    char *fname = fc_args.input_fnames[i];
	    rc = fc_read_file(fname, &chains[i], &fc_args.filter);
	    if (rc != 0) {
		fprintf(stderr, "%s: ERROR: could not read input [%s]\n",
			argv[0], fname);
		return -1;
	    }
	}
	n_chains = i;
    }

    rc = fc_merge_chains(chains, n_chains, &chunk);
    if (rc != 0) {
	fprintf(stderr, "%s: ERROR: could not merge input files\n",
		argv[0]);
	return -1;
    }

    for (i = 0; i < n_chains; i++) {
	rc = pcap_free_chain(&chains[i]);
    }

    fc_chunk_t aligned_chunk = chunk;
    if (fc_args.alignment > 0) {
	/*
	 * this is simple, but also lame
	 */
	aligned_chunk.count = 0;
	aligned_chunk.pkts =  NULL;
	for (i = 0; i < chunk.count; i++) {
	    if ((chunk.pkts[i].ts.ts_sec % fc_args.alignment) == 0) {
		aligned_chunk.count = chunk.count - i;
		aligned_chunk.pkts = chunk.pkts + i;
		break;
	    }
	}
    }

    FILE *fout = stdout;
    char *tmp_fname = NULL;

    if (fc_args.output_fname != NULL) {
	tmp_fname = (char *) malloc(strlen(fc_args.output_fname) + 2);
	if (tmp_fname == NULL) {
	    fprintf(stderr, "ERROR: malloc failed\n");
	    return -1;
	}

	sprintf(tmp_fname, "%s~", fc_args.output_fname);
	fout = fopen(tmp_fname, "w");
	if (fout == NULL) {
	    fprintf(stderr, "ERROR: fopen [%s] failed [%s]\n",
		    tmp_fname, strerror(errno));
	    free(tmp_fname);
	    return -1;
	}
    }

    if (aligned_chunk.count == 0) {
	/*
	 * if this happens, we try to print *something*
	 * meaningful, even though we can't assign a timespan
	 * a count that doesn't contain any packets at all
	 */

	for (i = 0; i < fc_args.n_queries; i++) {
	    fprintf(fout, "T,0,start_time,0,%s\n", fc_args.queries[i].query_str);
	}

	/* This diagnostic happens too often -- suppress */
	//fprintf(stderr, "%s: WARNING: no input packets\n",
	//	argv[0]);
    }
    else {
	fc_timespan_t timespan = {
		aligned_chunk.pkts[0].ts.ts_sec,
		fc_args.interval
	};

	for (i = 0; i < fc_args.n_queries; i++) {
	    fc_args.queries[i].chunk = &aligned_chunk;
	    rc = fc_compute_counts(
		    &aligned_chunk, &fc_args.queries[i],
		    &timespan, fc_args.normalized,
		    fout);
	    if (rc != 0) {
		fprintf(stderr,
			"%s: ERROR: could not execute query %d [%s]\n",
			argv[0], i, fc_args.queries[i].query_str);
		exit(1);
	    }
	}
    }

    /* If we're writing directly to a file, then once all of the output
     * has been rewritten, close the file and rename it to the final name.
     * This prevents partially-written output files from being mistaken
     * for complete output files.
     */
    if (fc_args.output_fname != NULL) {
	fclose(fout);
	rc = rename(tmp_fname, fc_args.output_fname);
	if (rc != 0) {
	    fprintf(stderr, "ERROR: rename of [%s] failed [%s]\n",
		    tmp_fname, strerror(errno));
	    return -1;
	}
	free(tmp_fname);
    }

    return rc;
}
