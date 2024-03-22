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

/*
 * Filter CSV data (from stdin) and print to stdout the rows with a
 * value in the nth column (assumed to signify an IPv4 address) do
 * not match any of the subnets in a file of subnet specs.
 */

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* The algorithm used by this program assumes that the
 * total number of addresses is relatively small, i.e.
 * less than a hundred thousand.  If there are millions
 * of addresses, then it's going to behave badly.  If
 * even larger than that, we give up.
 */
#define MIN_ALLOWED_PREFIX_LEN	(14)

/* If it takes more than 127 characters to define a
 * subnet, something is broken.
 */
#define SUBNET_BUFSIZE	(128)

/* Define a maximum length for each filtered CSV record.
 */
#define FILTER_BUFSIZE	(8192)


int
add_subnet(
	char *subnet_name,
	uint32_t **seen,
	uint32_t *seen_n,
	uint32_t *max_len)
{
    uint32_t subnet_size = 1;
    uint32_t subnet_mask = 0xffffffff;
    uint32_t base_addr;
    int rc;

    /* We use uint64_t for these values, even though a byte
     * should be large enough, in case the user provides bad
     * input.  The %hhu scanf format DOES NOT check whether
     * the input string actually fits in a byte; it simply
     * truncates the value.  So if we tried to use %hhu to
     * parse the input, it would "succeed" for something like
     * 1.2.3.4000, but the value of the low-order byte would
     * be 4000 % 256.
     *
     * Allowing a preposterously large value and then checking
     * it later will catch some potential errors, although
     * it's still not foolproof.
     */
    uint64_t q[4];
    uint64_t prefix_len;

    if (NULL != strchr(subnet_name, '/')) {

	rc = sscanf(subnet_name, "%lu.%lu.%lu.%lu/%lu",
		&q[3], &q[2], &q[1], &q[0], &prefix_len);
	if (rc != 5) {
	    fprintf(stderr, "ERROR: bad subnet spec [%s]\n", subnet_name);
	    return -1;
	}

	if (prefix_len > 32) {
	    fprintf(stderr, "ERROR: bad subnet spec [%s]\n", subnet_name);
	    return -1;
	}
	if (prefix_len < MIN_ALLOWED_PREFIX_LEN) {
	    fprintf(stderr, "ERROR: prefix for [%s] is too short [%lu < %u]\n",
		    subnet_name, prefix_len, MIN_ALLOWED_PREFIX_LEN);
	    return -1;
	}

	subnet_size = 1 << (32 - prefix_len);
	if (prefix_len == 32) {
	    subnet_mask = 0xffffffff;
	}
	else {
	    subnet_mask = ~(0xffffffff & (0xffffffff >> prefix_len));
	}
    }
    else {
	rc = sscanf(subnet_name, "%lu.%lu.%lu.%lu",
		&q[3], &q[2], &q[1], &q[0]);
	if (rc != 4) {
	    fprintf(stderr, "ERROR: bad subnet spec [%s]\n", subnet_name);
	    return -1;
	}
    }

    if (q[3] > 255 || q[2] > 255 || q[1] > 255 || q[0] > 255) {
	fprintf(stderr, "ERROR: bad subnet spec [%s]\n", subnet_name);
	return -1;
    }

    base_addr = (q[3] << 24) | (q[2] << 16) | (q[1] << 8) | q[0];
    base_addr &= subnet_mask;

    for (uint32_t i = 0; i < subnet_size; i++) {

	if (*seen_n == *max_len) {
	    *max_len = 2 * *max_len;
	    *seen = realloc(
		    (void *) *seen,
		    (size_t) (*max_len * sizeof(uint32_t)));
	    if (*seen == NULL) {
		fprintf(stderr, "ERROR: realloc failed\n");
		return -2;
	    }
	}

	(*seen)[*seen_n] = base_addr + i;
	*seen_n += 1;
    }

    return 0;
}

static int
read_subnets(
	char *fname,
	uint32_t **seen_addrs,
	uint32_t *seen_addrs_n,
	uint32_t *max_len)
{
    char buf[SUBNET_BUFSIZE];
    int rc;

    FILE *fin = fopen(fname, "r");
    if (fin == NULL) {
	fprintf(stderr, "ERROR: count not open [%s]\n", fname);
	return -1;
    }

    while (NULL != fgets(buf, SUBNET_BUFSIZE, fin)) {
	char *newline_pos = strrchr(buf, '\n');
	if (newline_pos == NULL) {
	    fprintf(stderr, "ERROR: line too long [%s...]\n", buf);
	    return -2;
	}
	else {
	    *newline_pos = 0;
	}

	char *comment = strchr(buf, '#');
	if (comment != NULL) {
	    *comment = '\0';
	}
	if (strlen(buf) == 0) {
	    continue;
	}

	rc = add_subnet(buf, seen_addrs, seen_addrs_n, max_len);
	if (rc != 0) {
	    return -1;
	}
    }

    fclose(fin);

    return 0;
}

static char *
strnthchr(
	char *str,
	int sep,
	int nth)
{
    char *pos = str;

    for (int i = 0; i < nth; i++) {
	pos = strchr(pos, sep);
	if (pos == NULL) {
	    return NULL;
	}
	pos += 1;
    }

    if (*pos) {
	return pos;
    }
    else {
	return NULL;
    }
}

static int
uint32_compare(
	const void *p0,
	const void *p1)
{
    uint32_t val0 = *(uint32_t *) p0;
    uint32_t val1 = *(uint32_t *) p1;

    /* Because we're dealing with unsigned numbers, we can't just
     * do the usual trick of returning val0 - val1 without some
     * ugly casting.  So we'll do things the explicit way and let the
     * compiler figure out how to optimize it.
     */
    if (val0 < val1) {
	return -1;
    }
    else if (val0 > val1) {
	return 1;
    }
    else {
	return 0;
    }
}

static void
usage(
	char *progname)
{

    fprintf(stderr, "usage: %s [-r] [-b FMT] [-F SEP] [-n NUM] [-s NET] [NETFILE]\n",
	    progname);
    fprintf(stderr, "%s",
    "\n"
    "Filter CSV from stdin by IP address in one column;\n"
    "write the unfiltered rows to stdout.\n"
    "\n"
    "-r      Reverse the filter.\n"
    "-b FMT  Use FMT as the address format [one of d, x, or q].\n"
    "        (d is decimal; x is hex; q is dotted decimal quads)\n"
    "-F SEP  Use the SEP character as the field separator\n"
    "        (default=,)\n"
    "-n NUM  Use the nth (one-based) column as the filter address\n"
    "        (default=1)\n"
    "-s NET  Filter by the given subnet (in addition to the NETFILE,\n"
    "        if any)\n"
    "NETFILE A file containing IPv4 addresses or subnets (in CIDR\n"
    "        notation), one per line, to filter.\n");
}

static int
parse_args(
	int argc,
	char **argv,
	int *sep,
	int *nth,
	int *format,
	int *inverse,
	char **fname,
	char **subnet)
{
    extern char *optarg;
    int opt;

    while ((opt = getopt(argc, argv, "b:F:n:rs:")) != -1) {
	switch (opt) {
	    case 'b':
		if (strlen(optarg) != 1) {
		    fprintf(stderr, "ERROR: bad format specifier\n");
		    return -1;
		}
		*format = optarg[0];
		break;
	    case 'n':
		*nth = strtoul(optarg, NULL, 0);
		if (*nth < 1) {
		    fprintf(stderr, "ERROR: nth must be >= 1\n");
		    return -1;
		}
		break;
	    case 'r':
		*inverse = 1;
		break;
	    case 's':
		*subnet = optarg;
		break;
	    case 'F':
		if (strlen(optarg) != 1) {
		    fprintf(stderr, "ERROR: bad seperator specifier\n");
		    return -1;
		}
		*sep = optarg[0];
		break;
	    default:
		fprintf(stderr, "ERROR: bad usage\n");
		usage(argv[0]);
		return -1;
	}
    }

    switch (*format) {
	case 'd':
	case 'x':
	case 'q':
	    break;
	default:
	    fprintf(stderr, "ERROR: bad format specifier (not d, x, or q)\n");
	    return -1;
    }

    if (optind == argc) {
	*fname = NULL;
    }
    else if (optind == (argc - 1)) {
	*fname = argv[optind];
    }
    else {
	fprintf(stderr, "ERROR: bad usage\n");
	usage(argv[0]);
	return -1;
    }

    return 0;
}

int
main(
	int argc,
	char **argv)
{
    /* we don't want to realloc too often, so we'll start
     * with a generous size -- and maybe we won't need to
     * realloc at all
     */
    char line[FILTER_BUFSIZE];
    uint32_t max_size = 64 * 1024;
    uint32_t curr_size = 0;
    int rc;

    int nth = 0;
    int sep = ',';
    int format = 'd';
    int inverse = 0;
    char *fname = NULL;
    char *subnet = NULL;

    void *loc = NULL;

    rc = parse_args(argc, argv, &sep, &nth, &format, &inverse,
	    &fname, &subnet);
    if (rc != 0) {
	return -1;
    }

    uint32_t *addresses = malloc(max_size * sizeof(uint32_t));
    if (addresses == NULL) {
	fprintf(stderr, "ERROR: malloc failed\n");
	return -1;
    }

    /* If there's neither an fname or a subnet on the commandline,
     * then we'll either filter everything or nothing (depending on
     * whether reverse was set)
     */
    if (fname != NULL) {
	rc = read_subnets(fname, &addresses, &curr_size, &max_size);
	if (rc != 0) {
	    return -1;
	}
    }
    else if (subnet != NULL) {
	rc = add_subnet(subnet, &addresses, &curr_size, &max_size);
	if (rc != 0) {
	    return -1;
	}
    }

    if (curr_size > 0) {
	qsort(addresses, curr_size, sizeof(uint32_t), uint32_compare);
    }

    uint64_t lineno = 0;
    while (NULL != fgets(line, FILTER_BUFSIZE, stdin)) {
	lineno++;

	if (NULL == strrchr(line, '\n')) {
	    fprintf(stderr, "WARNING: line %lu too long [%s]\n",
		    lineno, line);
	    continue;
	}

	char *field = strnthchr(line, sep, nth - 1);
	if (field) {
	    uint32_t addr = 0;

	    switch (format) {
		case 'd':
		    addr = strtoul(field, NULL, 10);
		    break;
		case 'x':
		    addr = strtoul(field, NULL, 16);
		    break;
		case 'q': {
		    uint64_t q[4];

		    rc = sscanf(field, "%lu.%lu.%lu.%lu",
			    &q[3], &q[2], &q[1], &q[0]);
		    if (rc != 4) {
			fprintf(stderr, "ERROR: bad address [%s]\n", field);
			return -1;
		    }
		    if (q[3] > 255 || q[2] > 255
			    || q[1] > 255 || q[0] > 255) {
			fprintf(stderr, "ERROR: bad address [%s]\n", field);
			return -1;
		    }

		    addr = (q[3] << 24) | (q[2] << 16) | (q[1] << 8) | q[0];
		}
		default:
		    fprintf(stderr,
			    "ERROR: unsupported format [%c]\n", format);
		    return -1;
	    }

	    loc = NULL;
	    if (addresses != NULL) {
		loc = bsearch(
			(void *) &addr, (void *) addresses, curr_size,
			sizeof(uint32_t), uint32_compare);
	    }
	    uint32_t unmatched = (loc == NULL) ? 1 : 0;
	    if (inverse ^ unmatched) {
		printf("%s", line);
	    }
	}
    }
}
