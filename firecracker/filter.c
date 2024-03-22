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

#include <stdlib.h>

#include "firecracker.h"

/*
 * filter specifiers look like the following:
 *
 * name[width]=value/...
 *
 * The name is the name of the field ot use (currently one of
 * S, D, P, E, or A) and the optional width is the prefix length
 * to use.  So, for example, if you wanted to match source address
 * 1.0.0.0/8, then you would use filter S8=1.0.0.0.
 *
 * for example:
 *
 * S24=1.1.1.0/D24=2.2.2.0/P=6
 *
 * This matches all packets from source /24 1.1.1.0 to destination /24
 * 2.2.2.0 using IP protocol 6.
 *
 * Note that to satisfy the filter, ALL of the fields must match.
 *
 * All numbers are in decimal.
 */

/*
 * This function is just for debugging, at least right now
 */
static int
fc_filter_pp(
	fc_filter_t *filter)
{
    fc_filter_field_t *fields = filter->fields;

    printf("filter n = %u\n", filter->n_fields);
    for (uint8_t i = 0; i < filter->n_fields; i++) {
	if (fields[i].width != 0) {
	    printf("  %c%u=%u\n",
		    fields[i].name, fields[i].width, fields[i].value);
	}
	else {
	    printf("  %c=%u\n", fields[i].name, fields[i].value);
	}
    }

    return 0;
}

/* FIXME: this function has some very sloppy error checking
 */
int
fc_str2filter(
	char *str,
	fc_filter_t *filter)
{
    uint32_t field_index = 0;
    char *endptr;
    int rc;

    while (*str != '\0') {
	switch (*str) {
	    case FC_FIELD_NAME_SADDR:
	    case FC_FIELD_NAME_DADDR: {
		uint8_t b3, b2, b1, b0;
		int consumed;

		filter->fields[field_index].name = *str;

		uint32_t width = strtol(str + 1, &endptr, 10);
		filter->fields[field_index].width = width;

		if (*endptr != '=') {
		    fprintf(stderr, "ERROR: expected '=' after field name\n");
		    return -1;
		}
		str = endptr + 1;
		rc = sscanf(str, "%hhu.%hhu.%hhu.%hhu%n",
			&b3, &b2, &b1, &b0, &consumed);
		if (rc != 4) {
		   fprintf(stderr, "ERROR: bad IP address [%s]\n", str);
		    return -1;
		}
		filter->fields[field_index].value =
			(b3 << 24) | (b2 << 16) | (b1 << 8) | b0;
		str += consumed;
		break;
	    }

	    case FC_FIELD_NAME_SPORT:
	    case FC_FIELD_NAME_DPORT:
	    case FC_FIELD_NAME_PROTO:
	    case FC_FIELD_NAME_SEC: {
		filter->fields[field_index].name = *str;

		uint32_t width = strtol(str + 1, &endptr, 10);
		filter->fields[field_index].width = width;

		if (*endptr != '=') {
		   fprintf(stderr, "ERROR: expected '=' after field name\n");
		    return -1;
		}
		str = endptr + 1;
		uint32_t value = strtol(str, &endptr, 10);
		filter->fields[field_index].value = value;

		if (endptr != str + 1) {
		    str = endptr;
		}
		else {
		    str++;
		}

		break;
	    }
	    default:
	       fprintf(stderr, "ERROR: bad field name [%c]\n", *str);
	       return -1;
	}

	field_index++;

	if (*str == '\0') {
	    break;
	}
	else if (*str == '/') {
	    str++;
	}
	else {
	    return -1;
	}
    }

    filter->n_fields = field_index;

    return 0;
}

int
fc_filter_pkt(
	fc_pkt_t *pkt,
	fc_filter_t *filter)
{

    for (uint8_t i = 0; i < filter->n_fields; i++) {
	fc_field_name_t name = filter->fields[i].name;
	uint32_t val1 = fetch_field(pkt, name);
	uint32_t val2 = filter->fields[i].value;
	uint8_t width = filter->fields[i].width;

	if (width > 0) {
	    uint32_t mask = 0xffffffff & ~((1 << (32 - width)) - 1);

	    val1 &= mask;
	    val2 &= mask;
	}

	if (val1 != val2) {
	    return 0;
	}
    }

    return 1;
}

int
fc_apply_filter(
	fc_filter_t *filter,
	fc_chunk_t *chunk,
	uint64_t base,
	uint64_t count,
	fc_elems_t *elems)
{
    /*
     * TODO: sanity check that base and count fit in the given chunk
     */

    uint64_t n_elem = count;

    elems->order = (uint64_t *) malloc(n_elem * sizeof(uint64_t));
    if (elems->order == NULL) {
	fprintf(stderr, "ERROR: malloc failed\n");
	return -1;
    }

    /* Note that we might (usually) allocate more space than necessary,
     * but we don't know how much space we need until we apply the
     * filter.
     */

    uint64_t matches = 0;
    for (uint64_t i = 0; i < n_elem; i++) {
	if (fc_filter_pkt(&chunk->pkts[base + i], filter)) {
	    elems->order[matches++] = base + i;
	}
    }

    elems->count = matches;

    return 0;
}
