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
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "firecracker.h"

/*
Example commandline:

    fc5conf -d foo.fc5 f1.pcap f2.pcap f3.csv.gz

Create an fc5 file named foo.fc5 containing the fc5 representation
of the data in f1.pcap, f2.pcap, and f3.csv.gz.

The input files do not all need to be the same format (any combination
of pcap, csv, and fc5 is allowd), and can be a mix of compressed
(using gzip or lz4) and uncompressed.

The reason to convert files to fc5 is because fc5 is fairly compact
(and can be compressed to make it even more so), and loading fc5 is
very fast compared to the effort of parsing pcap or csv files.
So if you have a workflow that involves running firecracker many
times over the same inputs, it may make sense to convert the inputs
to fc5 first.
*/

#define MAX_INPUT_FILES	(7 * 24)

typedef struct {
    char **input_fnames;
    char *dump_file;
} fc5conv_args_t;

static void
usage(char *const prog)
{
    printf("usage: %s [-h] [-d FNAME] input1 .. inputN\n", prog);
    printf("    -h          Print help message and exit.\n");
    printf("    -d FNAME    Dump the input to FNAME in fc5 format.\n");
    printf("                The default is to dump to stdout.\n");

    return;
}

static int
parse_args(
	int argc,
	char *const argv[], 
	fc5conv_args_t *args)
{
    int opt;

    args->dump_file = NULL;

    while ((opt = getopt(argc, argv, "d:h")) != -1) {
	switch (opt) {
	    case 'd':
		args->dump_file = optarg;
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

    args->input_fnames = (char **) argv + optind;

    return 0;
}

int
main(
	int argc,
	char *const argv[])
{
    fc5conv_args_t fc_args;
    uint32_t i;

    int rc = parse_args(argc, argv, &fc_args);
    if (rc != 0) {
	return -1;
    }

    pkt_chain_t chains[MAX_INPUT_FILES];
    fc_chunk_t chunk;

    if (fc_args.input_fnames[0] == NULL) {
	fprintf(stderr, "%s: ERROR: no input files given\n",
		argv[0]);
	return -1;
    }

    for (i = 0; fc_args.input_fnames[i] != NULL; i++) {

	if (i >= MAX_INPUT_FILES) {
	    fprintf(stderr, "%s: ERROR: too many input files (max=%d)\n",
		    argv[0], MAX_INPUT_FILES);
	    return -1;
	}

	char *fname = fc_args.input_fnames[i];
	rc = fc_read_file(fname, &chains[i], NULL);
	if (rc != 0) {
	    fprintf(stderr, "%s: ERROR: could not read input [%s]\n",
		    argv[0], fname);
	    return -1;
	}
    }
    uint32_t n_chains = i;

    rc = fc_merge_chains(chains, n_chains, &chunk);
    if (rc != 0) {
	fprintf(stderr, "%s: ERROR: could not merge input files\n",
		argv[0]);
	return -1;
    }

    FILE *fout = stdout;
    if (fc_args.dump_file != NULL) {
	fout = fopen(fc_args.dump_file, "w+");
	if (fout == NULL) {
	    fprintf(stderr, "%s: ERROR: could not open dump file [%s]\n",
		    argv[0], fc_args.dump_file);
	    exit(1);
	}
    }

    rc = fc_fc5_write(fout, &chunk);
    if (rc != 0) {
	fprintf(stderr, "%s: ERROR: could not write dump file [%s]\n",
		argv[0], fc_args.dump_file);
	exit(1);
    }

    if (fc_args.dump_file != NULL) {
	fclose(fout);
    }

    return 0;
}
