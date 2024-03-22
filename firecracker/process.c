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
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include "firecracker.h"

int
fc_str2query(
	char *str,
	fc_query_t *query)
{
    uint32_t field_index = 0;
    char *endptr;

    while (*str != '\0') {
	switch (*str) {
	    case FC_FIELD_NAME_SADDR:
	    case FC_FIELD_NAME_DADDR:
	    case FC_FIELD_NAME_SPORT:
	    case FC_FIELD_NAME_DPORT:
	    case FC_FIELD_NAME_PROTO:
	    case FC_FIELD_NAME_SEC:
	    case FC_FIELD_NAME_USEC:
	    case FC_FIELD_NAME_LEN: {
		query->fields[field_index].name = *str;

		/* see if there's a width... */
		uint32_t width = strtol(str + 1, &endptr, 10);
		query->fields[field_index].width = width;
		field_index++;

		if (endptr != str + 1) {
		    str = endptr;
		}
		else {
		    str++;
		}

		break;
	    }
	    default:
	       printf("oops\n");
	       return -1;
	}
    }

    query->query_str = strdup(str);
    if (query->query_str == NULL) {
	return -1;
    }
    query->n_fields = field_index;

    /* show_max will get filled in later, if needed */
    query->show_max = 0;

    return 0;
}

inline uint32_t
fetch_field(
	fc_pkt_t *pkt,
	fc_field_name_t name)
{

    switch (name) {
	case FC_FIELD_NAME_SADDR:
	    return pkt->saddr;
	case FC_FIELD_NAME_DADDR:
	    return pkt->daddr;
	case FC_FIELD_NAME_SPORT:
	    return pkt->sport;
	case FC_FIELD_NAME_DPORT:
	    return pkt->dport;
	case FC_FIELD_NAME_PROTO:
	    return pkt->proto;
	case FC_FIELD_NAME_LEN:
	    return pkt->len;
	case FC_FIELD_NAME_SEC:
	    return pkt->ts.ts_sec;
	case FC_FIELD_NAME_USEC:
	    return pkt->ts.ts_usec;
	default:
	    printf("oops! fetch_field %d\n", name);
	    return 0;
    }
}

/*
 * Comparison function for stable sorting, according to the
 * fields specified in the query
 *
 * Note that the field widths are IGNORED for this comparison,
 * and ties are broken with the timestamp (in order to provide
 * stability, if we can assume that the pkts arrive in ascending
 * time order)
 */
static int
comparator_sort(
	const void *p1,
	const void *p2,
	void *arg)
{
    fc_query_t *query = (fc_query_t *) arg;
    fc_pkt_t *pkts = query->chunk->pkts;
    uint64_t ind1 = *(uint64_t *) p1;
    uint64_t ind2 = *(uint64_t *) p2;
    fc_pkt_t *pkt1 = pkts + ind1;
    fc_pkt_t *pkt2 = pkts + ind2;

    for (uint8_t i = 0; i < query->n_fields; i++) {
	fc_field_name_t name = query->fields[i].name;
	uint32_t val1 = fetch_field(pkt1, name);
	uint32_t val2 = fetch_field(pkt2, name);

	if (val1 < val2) {
	    return -1;
	}
	else if (val1 > val2) {
	    return 1;
	}
    }

    /*
     * If there's no difference, use the timestamp to
     * break the tie, if possible
     */
    fc_timeval_t ts1 = pkt1->ts;
    fc_timeval_t ts2 = pkt2->ts;

    if (ts1.ts_sec < ts2.ts_sec) {
	return -1;
    }
    else if (ts1.ts_sec > ts2.ts_sec) {
	return 1;
    }
    else if (ts1.ts_usec < ts2.ts_usec) {
	return -1;
    }
    else if (ts1.ts_usec > ts2.ts_usec) {
	return 1;
    }
    else {
	return 0;
    }
}


/*
 * Comparison function for grouping, according to the given query.
 * NOT intended to be used as a sorting comparison function!  Does
 * not use the same type signature as a sorting comparison function;
 * is completely specialized to the purpose of grouping adjacent
 * pkts.
 *
 * Assumes that only adjacent items in the sorted order are compared,
 * and that the order is already total (so there's no need to break
 * ties with the timestamps).  Unlike comparator_sort, this function
 * DOES use the field widths when comparing two values
 */
static int
comparator_group(
	uint64_t ind1,
	uint64_t ind2,
	fc_query_t *query)
{
    fc_pkt_t *pkts = query->chunk->pkts;
    fc_pkt_t *pkt1 = pkts + ind1;
    fc_pkt_t *pkt2 = pkts + ind2;

    for (uint8_t i = 0; i < query->n_fields; i++) {
	fc_field_name_t name = query->fields[i].name;
	uint32_t val1 = fetch_field(pkt1, name);
	uint32_t val2 = fetch_field(pkt2, name);

	uint8_t width = query->fields[i].width;
	if (width > 0) {
	    uint32_t mask = 0xffffffff & ~((1 << (32 - width)) - 1);

	    // printf("val1 %u val2 %u mask %x ", val1, val2, mask);
	    val1 &= mask;
	    val2 &= mask;
	    // printf("m1 %u m2 %u\n", val1, val2);
	}

	if (val1 < val2) {
	    return -1;
	}
	else if (val1 > val2) {
	    return 1;
	}
    }

    return 0;
}

/*
 * Create an index for a segment of the given chunk (starting
 * at base, and containing count elements) using the given query
 */
static int
fc_create_index(
	fc_chunk_t *chunk,
	uint64_t base,
	uint64_t count,
	fc_query_t *query,
	fc_elems_t *elems)
{

    /* TODO: sanity checking: make sure that base and count are possible
     * give the number of elements in the chunk!
     */

    elems->count = count;

    elems->order = (uint64_t *) malloc(elems->count * sizeof(uint64_t));
    if (elems->order == NULL) {
	fprintf(stderr, "ERROR: malloc failed\n");
	return -1;
    }

    for (uint64_t i = 0; i < elems->count; i++) {
	elems->order[i] = base + i;
    }

    qsort_r(elems->order, elems->count, sizeof(uint64_t),
	    comparator_sort, query);

    return 0;
}

static int
print_count(
	uint64_t count,
	fc_pkt_t *pkt,
	fc_query_t *query,
	uint32_t start_time,
	int normalized,
	uint64_t total_count,
	FILE *fout)
{

    if (normalized) {
	double fraction = ((double) count) / ((double) total_count);
	fprintf(fout, "N,%g,start_time,%d", fraction , start_time);
    }
    else {
	fprintf(fout, "C,%ld,start_time,%d", count, start_time);
    }

    for (int i = 0; i < query->n_fields; i++) {
	fc_field_name_t name = query->fields[i].name;
	uint8_t width = query->fields[i].width;
	uint32_t mask = 0xffffffff & ~((1 << (32 - width)) - 1);
	uint32_t val = mask & fetch_field(pkt, name);

	if ((name == 'S') || (name == 'D')) {
	    if (width > 0 && width != 32) {
		fprintf(fout, ",%c%u,%u.%u.%u.%u/%u", name, width,
			0xff & (val >> 24), 0xff & (val >> 16),
			0xff & (val >> 8), 0xff & val,
			width);
	    }
	    else {
		fprintf(fout, ",%c,%u.%u.%u.%u", name,
			0xff & (val >> 24), 0xff & (val >> 16),
			0xff & (val >> 8), 0xff & val);
	    }
	}
	else {
	    if (width > 0 && width != 32) {
		fprintf(fout, ",%c%u,%u", name, width, val);
	    }
	    else {
		fprintf(fout, ",%c,%u", name, val);
	    }
	}
    }
    if (query->show_query) {
	fprintf(fout, ",%s", query->query_str);
    }
    fprintf(fout, "\n");

    return 0;
}

typedef struct {
    uint64_t index;
    uint64_t count;
} fc_count_order_t;

static int
count_compare(
	const void *p1,
	const void *p2)
{
    fc_count_order_t *o1 = (fc_count_order_t *) p1;
    fc_count_order_t *o2 = (fc_count_order_t *) p2;

    /* This looks backwards because we sort in descending order */
    return o2->count - o1->count;
}

static int
fc_compute_counts_subset(
	fc_chunk_t *chunk,
	uint64_t base,
	uint64_t count,
	fc_query_t *query,
	uint32_t start_time,
	int print_normalized,
	FILE *fout)
{
    fc_elems_t elems;
    uint64_t tail = 0;
    int rc;

    if (count == 0) {
	fprintf(fout, "T,%d,start_time,%d,%s\n",
		0, start_time, query->query_str);
	return 0;
    }

    rc = fc_create_index(chunk, base, count, query, &elems);
    if (rc != 0) {
	fprintf(stderr, "ERROR: could not create index\n");
	return -1;
    }

    /*
     * TODO: This makes a worst-case assumption about how many unique
     * items there will be.  If we start to feel memory pressure
     * then we should allocate this lazily.
     */
    fc_count_order_t *counts = malloc(elems.count * sizeof(fc_count_order_t));
    if (counts == NULL) {
	fprintf(stderr, "ERROR: malloc failed\n");
	return -1;
    }

    uint64_t n_counts = 0;
    uint64_t *order = elems.order;

    while (tail < elems.count) {
	uint64_t subcount = 1;
	uint64_t head = tail;

	for (tail = head + 1; tail < elems.count; tail++) {
	    if (comparator_group(order[head], order[tail], query) != 0) {
		break;
	    }
	    subcount++;
	}
	counts[n_counts].index = order[head];
	counts[n_counts].count = subcount;
	n_counts++;
    }

    if (query->show_max >= 0) {
	if (query->show_max > 0) {
	    qsort(counts, n_counts, sizeof(fc_count_order_t), count_compare);
	}
	if (query->show_max >= 0 && query->show_max < n_counts) {
	    n_counts = query->show_max;
	}
    }

    for (uint64_t i = 0; i < n_counts; i++) {
	print_count(counts[i].count, &chunk->pkts[counts[i].index], query,
		start_time, 0, elems.count, fout);
    }

    if (print_normalized) {
	for (uint64_t i = 0; i < n_counts; i++) {
	    print_count(counts[i].count, &chunk->pkts[counts[i].index], query,
		    start_time, 1, elems.count, fout);
	}
    }

    fprintf(fout, "T,%ld,start_time,%d,%s\n",
	    elems.count, start_time, query->query_str);

    free(elems.order);
    free(counts);

    return 0;
}

int
fc_compute_counts(
	fc_chunk_t *chunk,
	fc_query_t *query,
	fc_timespan_t *timespan,
	int normalized,
	FILE *fout)
{
    int rc = 0;

    if ((timespan == NULL) || (timespan->length_sec == 0)) {
	rc = fc_compute_counts_subset(chunk, 0, chunk->count,
		query, chunk->pkts[0].ts.ts_sec,
		normalized, fout);
	if (rc != 0) {
	    return -1;
	}
    }
    else {
	uint64_t start = 0;
	uint64_t start_span = timespan->base_sec;
	uint64_t end_span = start_span + timespan->length_sec;
	uint64_t count;
	uint64_t i;

	for (i = 0; i < chunk->count; i++) {
	    uint64_t curr_time = chunk->pkts[i].ts.ts_sec;

	    if (curr_time >= end_span) {
		count = i - start;
		rc = fc_compute_counts_subset(chunk, start, count,
			query, start_span, normalized, fout);
		if (rc != 0) {
		    return -1;
		}

		start = i;
		start_span = end_span;
		end_span += timespan->length_sec;

		/*
		 * We've just moved forward end_span -- but it's
		 * possible that the curr_time is still greater
		 * than end_span, because we've hit an empty span.
		 * Keep iterating until we find a span that contains
		 * at least one packet.
		 */
		while (curr_time > end_span) {
		    /*
		     * call compute_counts_subset with a count of 0
		     * so that the timespan will be recorded (with
		     * a total count of 0)
		     */
		    rc = fc_compute_counts_subset(chunk, start, 0,
			    query, start_span, normalized, fout);
		    if (rc != 0) {
			return -1;
		    }

		    start_span = end_span;
		    end_span += timespan->length_sec;
		}
	    }
	}

	count = i - start;
	if (count > 0) {
	    rc = fc_compute_counts_subset(chunk, start, count,
		    query, start_span, normalized, fout);
	    if (rc != 0) {
		return -1;
	    }
	}
    }

    return rc;
}
