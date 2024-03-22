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


void
print_ipv4addr(
	uint32_t addr)
{

    printf("%d.%d.%d.%d",
	    (addr >> 24) & 0xff, (addr >> 16) & 0xff,
	    (addr >> 8) & 0xff, addr & 0xff);
}

void
print_port(
	uint16_t port)
{

    printf("%d", port & 0xffff);
}

void
print_proto(
	uint8_t proto)
{

    switch (proto) {
	case 6:
	    printf("tcp");
	    break;
	case 17:
	    printf("udp");
	    break;
	case 1:
	    printf("icmp");
	    break;
	/* Any others we want to add here? */

	default:
	    printf("%d", proto);
	    break;
    }
}

void
print_pkt(
	fc_pkt_t *pkt)
{

    print_ipv4addr(pkt->saddr);
    printf(" ");
    print_ipv4addr(pkt->daddr);
    printf(" ");
    print_port(pkt->sport);
    printf(" ");
    print_port(pkt->dport);
    printf(" ");
    print_proto(pkt->proto);
}




