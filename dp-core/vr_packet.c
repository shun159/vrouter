/*
 * vr_packet.c -- packet handling helpers
 *
 * Copyright (c) 2013 Juniper Networks, Inc. All rights reserved.
 */
#include <vr_os.h>
#include <vr_packet.h>

struct vr_packet *
pkt_copy(struct vr_packet *pkt, unsigned short off, unsigned short len)
{
    struct vr_packet *pkt_c;
    unsigned short head_space;

    /*
     * one eth header for agent, and one more for packets from
     * tun interfaces
     */
    head_space = (2 * sizeof(struct vr_eth)) + sizeof(struct agent_hdr);
    pkt_c = vr_palloc(head_space + len);
    if (!pkt_c)
        return pkt_c;

    pkt_c->vp_data += head_space;
    pkt_c->vp_tail += head_space;
    if (vr_pcopy(pkt_data(pkt_c), pkt, off, len) < 0) {
        PKT_LOG(VP_DROP_MISC, pkt, 0, VR_PACKET_C, __LINE__);
        vr_pfree(pkt_c, VP_DROP_MISC);
        return NULL;
    }
    pkt_pull_tail(pkt_c, len);

    pkt_c->vp_if = pkt->vp_if;
    pkt_c->vp_flags = pkt->vp_flags;
    pkt_c->vp_cpu = pkt->vp_cpu;
    pkt_c->vp_network_h = 0;

    return pkt_c;
}

struct vr_packet *
pkt_cow(struct vr_packet *pkt, unsigned short head_room)
{
    struct vr_packet *clone_pkt;

    /* Clone the packet */
    clone_pkt = vr_pclone(pkt);
    if (!clone_pkt) {
        return NULL;
    }

    /* Increase the head space by the head_room */
    if (vr_pcow(&clone_pkt, head_room)) {
        PKT_LOG(VP_DROP_PCOW_FAIL, pkt, 0, VR_PACKET_C, __LINE__);
        vr_pfree(clone_pkt, VP_DROP_PCOW_FAIL);
        return NULL;
    }

    /* Copy the ttl from old packet */
    clone_pkt->vp_ttl = pkt->vp_ttl;

    return clone_pkt;
}

bool
vr_ip_proto_pull(struct vr_ip *iph)
{
    unsigned char proto = iph->ip_proto;

    if ((proto == VR_IP_PROTO_TCP) || (proto == VR_IP_PROTO_UDP) ||
        (proto == VR_IP_PROTO_ICMP) || (proto == VR_IP_PROTO_SCTP)) {
        return true;
    }

    return false;
}

bool
vr_ip6_proto_pull(struct vr_ip6 *ip6h)
{
    unsigned char proto = ip6h->ip6_nxt;

   if ((proto == VR_IP_PROTO_TCP) || (proto == VR_IP_PROTO_UDP) ||
       (proto == VR_IP_PROTO_ICMP6) || (proto == VR_IP_PROTO_SCTP) ||
       (proto == VR_IP6_PROTO_FRAG)) {
        return true;
    }

    return false;
}

/**
 * vr_ip_transport_parse - parse IP packet to reach the L4 header
 */
int
vr_ip_transport_parse(struct vr_ip *iph, struct vr_ip6 *ip6h,
                      void **thp, unsigned int frag_size,
                      void (do_tcp_mss_adj)(struct tcphdr *, unsigned short,
                                          unsigned char),
                      unsigned int *hlenp,
                      unsigned short *th_csump,
                      unsigned int *tcph_pull_lenp,
                      unsigned int *pull_lenp)
{
    unsigned char *thdr;
    unsigned short ip_proto;
    bool thdr_valid = false, icmp_pl_frag_hdr = false;
    unsigned int hlen = 0, tcph_pull_len = 0;
    unsigned int pull_len = *pull_lenp;
    struct vr_tcp *tcph = NULL;
    unsigned short th_csum = 0;
    struct vr_icmp *icmph = NULL;
    struct vr_ip *icmp_pl_iph = NULL;
    struct vr_ip6 *icmp_pl_ip6h = NULL;
    struct vr_ip6_frag *v6_frag;


    /* Note: iph is set for both ipv4 and ipv6 cases */
    if (iph) {
        if (vr_ip_is_ip6(iph)) {
            if (ip6h) {
                ip_proto = ip6h->ip6_nxt;
                hlen = sizeof(struct vr_ip6);
                if (ip_proto == VR_IP6_PROTO_FRAG) {
                    pull_len += sizeof(struct vr_ip6_frag);
                    if (frag_size < pull_len) {
                        return PKT_RET_SLOW_PATH;
                    }

                    v6_frag = (struct vr_ip6_frag *)((char *)ip6h + hlen);
                    ip_proto = v6_frag->ip6_frag_nxt;
                    hlen += sizeof(struct vr_ip6_frag);
                }
                thdr_valid = vr_ip6_transport_header_valid(ip6h);
            } else {
                return PKT_RET_UNHANDLED;
            }
        } else if (vr_ip_is_ip4(iph)) {
            ip_proto = iph->ip_proto;
            /*
             * Account for IP options
             */
            thdr_valid = vr_ip_transport_header_valid(iph);
            if (thdr_valid) {
                hlen = iph->ip_hl * 4;
                pull_len += (hlen - sizeof(struct vr_ip));
            }
        } else {
            return PKT_RET_UNHANDLED;
        }

        if (thdr_valid) {
            tcph_pull_len = pull_len;
            if (thp)
                *thp = (char *)iph + hlen;

            if (ip_proto == VR_IP_PROTO_TCP) {
                pull_len += sizeof(struct vr_tcp);
            } else if (ip_proto == VR_IP_PROTO_UDP) {
                pull_len += sizeof(struct vr_udp);
            } else if ((ip_proto == VR_IP_PROTO_ICMP) ||
                       (ip_proto == VR_IP_PROTO_ICMP6)) {
                pull_len += sizeof(struct vr_icmp);
            } else if (ip_proto == VR_IP_PROTO_SCTP) {
               pull_len += sizeof(struct vr_sctp);
            }

            if (frag_size < pull_len) {
                return PKT_RET_SLOW_PATH;
            }


            if (ip_proto == VR_IP_PROTO_TCP) {
                /*
                 * Account for TCP options
                 */
                tcph = (struct vr_tcp *)((char *)iph + hlen);

                /*
                 * If SYN, do TCP MSS adjust using passed callback, or send it
                 * to the slow path.
                 */
                if ((ntohs(tcph->tcp_offset_r_flags) & VR_TCP_FLAG_SYN) &&
                        vr_to_vm_mss_adj) {
                    if (do_tcp_mss_adj) {
                        /* Kernel will never get here, it will return slow path */
                        do_tcp_mss_adj((struct tcphdr *)tcph,
                                            VROUTER_L2_OVERLAY_LEN, hlen);
                    } else {
                        return PKT_RET_SLOW_PATH;
                    }
                }

                if ((VR_TCP_OFFSET(tcph->tcp_offset_r_flags) * 4) >
                        (sizeof(struct vr_tcp))) {
                    pull_len += ((VR_TCP_OFFSET(tcph->tcp_offset_r_flags) * 4) -
                                    (sizeof(struct vr_tcp)));

                    if (frag_size < pull_len) {
                        return PKT_RET_SLOW_PATH;
                    }
                }
                th_csum = tcph->tcp_csum;
            } else if (ip_proto == VR_IP_PROTO_ICMP) {
                icmph = (struct vr_icmp *)((unsigned char *)iph + hlen);
                th_csum = icmph->icmp_csum;
                if (vr_icmp_error(icmph)) {
                    pull_len += sizeof(struct vr_ip);
                    if (frag_size < pull_len)
                        return PKT_RET_SLOW_PATH;
                    icmp_pl_iph = (struct vr_ip *)(icmph + 1);
                    pull_len += (icmp_pl_iph->ip_hl * 4) - sizeof(struct vr_ip);
                    if (frag_size < pull_len)
                        return PKT_RET_SLOW_PATH;
                    if (vr_ip_proto_pull(icmp_pl_iph)) {
                        if (icmp_pl_iph->ip_proto == VR_IP_PROTO_TCP)
                            pull_len += sizeof(struct vr_tcp);
                        else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_UDP)
                            pull_len += sizeof(struct vr_udp);
                        else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_SCTP)
                            pull_len += sizeof(struct vr_sctp);
                        else
                            pull_len += sizeof(struct vr_icmp);

                        if (frag_size < pull_len)
                            return PKT_RET_SLOW_PATH;

                        if (icmp_pl_iph->ip_proto == VR_IP_PROTO_TCP) {
                            th_csum = ((struct vr_tcp *)
                                        ((unsigned char *)icmp_pl_iph +
                                        icmp_pl_iph->ip_hl * 4))->tcp_csum;
                        } else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_UDP) {
                            th_csum = ((struct vr_udp *)
                                        ((unsigned char *)icmp_pl_iph +
                                        icmp_pl_iph->ip_hl * 4))->udp_csum;
                        } else if (icmp_pl_iph->ip_proto == VR_IP_PROTO_ICMP) {
                            th_csum = ((struct vr_icmp *)
                                        ((unsigned char *)icmp_pl_iph +
                                        icmp_pl_iph->ip_hl * 4))->icmp_csum;
                        }
                    }
                }
            } else if (iph->ip_proto == VR_IP_PROTO_UDP) {
                th_csum = ((struct vr_udp *)
                            ((unsigned char *)iph + hlen))->udp_csum;
            } else if ((ip_proto == VR_IP_PROTO_ICMP6) && ip6h) {
                icmph = (struct vr_icmp *)((unsigned char *)ip6h + hlen);
                if (icmph->icmp_type == VR_ICMP6_TYPE_NEIGH_SOL) {
                    /*
                     * We do not know if neighbour option of length
                     * VR_ETHER_ALEN is not at all there or not in this
                     * frag. So we will calculate the length to
                     * be inclusive of both Target address and neighbour
                     * option. If option is not preset, slow path would
                     * take care of it
                     */
                    pull_len += sizeof(struct vr_neighbor_option) +
                                VR_IP6_ADDRESS_LEN + VR_ETHER_ALEN;
                } else if (icmph->icmp_type == VR_ICMP6_TYPE_ROUTER_SOL) {
                    pull_len += 8;
                } else if (vr_icmp6_error(icmph)) {
                    pull_len += sizeof(struct vr_ip6);
                    if (frag_size < pull_len)
                        return PKT_RET_SLOW_PATH;
                    icmp_pl_ip6h = (struct vr_ip6 *)(icmph + 1);
                    ip_proto = icmp_pl_ip6h->ip6_nxt;
                    if (vr_ip6_proto_pull(icmp_pl_ip6h)) {
                        if (icmp_pl_ip6h->ip6_nxt == VR_IP_PROTO_TCP)
                            pull_len += sizeof(struct vr_tcp);
                        else if (icmp_pl_ip6h->ip6_nxt == VR_IP_PROTO_UDP)
                            pull_len += sizeof(struct vr_udp);
                        else if (icmp_pl_ip6h->ip6_nxt == VR_IP_PROTO_SCTP)
                            pull_len += sizeof(struct vr_sctp);
                        else if (icmp_pl_ip6h->ip6_nxt == VR_IP6_PROTO_FRAG) {
                            pull_len += sizeof(struct vr_ip6_frag);
                            icmp_pl_frag_hdr = true;
                        } else
                            pull_len += sizeof(struct vr_icmp);

                        if (frag_size < pull_len)
                            return PKT_RET_SLOW_PATH;

                        if (icmp_pl_frag_hdr) {
                            v6_frag = (struct vr_ip6_frag *)
                                ((unsigned char *)icmp_pl_ip6h +
                                 sizeof(struct vr_ip6));
                            ip_proto = v6_frag->ip6_frag_nxt;
                            thdr = (unsigned char *)v6_frag +
                                        sizeof(struct vr_ip6_frag);
                        } else {
                            thdr = (unsigned char *)icmp_pl_ip6h +
                                sizeof(struct vr_ip6);
                        }

                        if (ip_proto == VR_IP_PROTO_TCP) {
                            th_csum = ((struct vr_tcp *)thdr)->tcp_csum;
                            if (icmp_pl_frag_hdr)
                                pull_len += sizeof(struct vr_tcp);
                        } else if (ip_proto == VR_IP_PROTO_UDP) {
                            th_csum = ((struct vr_udp *)thdr)->udp_csum;
                            if (icmp_pl_frag_hdr)
                                pull_len += sizeof(struct vr_udp);
                        } else if (ip_proto == VR_IP_PROTO_ICMP6) {
                            th_csum = ((struct vr_icmp *)thdr)->icmp_csum;
                            if (icmp_pl_frag_hdr)
                                pull_len += sizeof(struct vr_icmp);
                        } else if (ip_proto == VR_IP_PROTO_SCTP) {
                            if (icmp_pl_frag_hdr)
                                pull_len += sizeof(struct vr_sctp);
                        }
                    }
                }

                if (frag_size < pull_len)
                    return PKT_RET_SLOW_PATH;
            }
        }
    }

    if (hlenp)
        *hlenp = hlen;
    if (th_csump)
        *th_csump = th_csum;
    if (tcph_pull_lenp)
        *tcph_pull_lenp = tcph_pull_len;
    *pull_lenp = pull_len;

    return 0;
}

/**
 * vr_inner_pkt_parse - parse inner packet transported in MPLS-o-UDP, MPLS-o-GRE
 * or VXLAN tunnel.
 */

int
vr_inner_pkt_parse(unsigned char *va, int (*tunnel_type_cb)(unsigned int,
                unsigned int, unsigned short *), int *encap_type,
                int *pkt_typep, unsigned int *pull_lenp,
                unsigned int frag_size, struct vr_ip **iphp,
                struct vr_ip6 **ip6hp, unsigned short gre_udp_encap,
                unsigned char ip_proto)
{
    unsigned short eth_proto;
    unsigned int pull_len = *pull_lenp;
    unsigned int label, control_data;
    int pkt_type = 0;
    struct vr_ip6 *ip6h = NULL;
    struct vr_ip *iph = NULL;
    struct vr_eth *eth = NULL;
    unsigned int mpls_label_len = VR_MPLS_HDR_LEN;

    if ((ip_proto == VR_IP_PROTO_GRE && gre_udp_encap == VR_GRE_PROTO_MPLS_NO) ||
        (ip_proto == VR_IP_PROTO_UDP && vr_mpls_udp_port(ntohs(gre_udp_encap)))) {

        *encap_type = PKT_ENCAP_MPLS;
        /* Take into consideration, the MPLS header and 4 bytes of
         * control information that might exist for L2 packet */
        if (frag_size < (pull_len + VR_MPLS_HDR_LEN +
                                VR_L2_CTRL_DATA_LEN)) {
            return PKT_RET_SLOW_PATH;
        }

        label = ntohl(*(uint32_t *)(va + pull_len));
        if (!(label & VR_MPLS_LABEL_STACK_BIT_MASK)
              && ((label >> VR_MPLS_LABEL_SHIFT) == VR_MPLS_LABEL_MASK)) {
            // ignore outer label
            label = ntohl(*(uint32_t *)(va + pull_len + VR_MPLS_HDR_LEN));
            mpls_label_len = 2*VR_MPLS_HDR_LEN;
        }

        control_data = *(uint32_t *)(va + pull_len + mpls_label_len);

        /* Identify whether the packet is L2 or not using the label and
         * control data */
        pkt_type = tunnel_type_cb(label, control_data, NULL);
        if (pkt_type <= 0)
            return PKT_RET_UNHANDLED;

        if (pkt_type == PKT_MPLS_TUNNEL_L3) {
            /* L3 packet */
            iph = (struct vr_ip *) (va + pull_len + mpls_label_len);
            if (vr_ip_is_ip6(iph)) {
                ip6h = (struct vr_ip6 *)iph;
                pull_len += mpls_label_len + sizeof(struct vr_ip6);
            } else if (vr_ip_is_ip4(iph)) {
                pull_len += mpls_label_len + sizeof(struct vr_ip);
            } else {
                return PKT_RET_UNHANDLED;
            }
        } else if (pkt_type == PKT_MPLS_TUNNEL_L2_MCAST) {
            /* L2 Multicast packet with control information and
             * Vxlan header. Vxlan header contains IP + UDP + Vxlan */
            eth = (struct vr_eth *)(va + pull_len + mpls_label_len +
                    VR_L2_CTRL_DATA_LEN + VR_VXLAN_HDR_LEN);
            pull_len += mpls_label_len + VR_L2_CTRL_DATA_LEN +
                            VR_VXLAN_HDR_LEN + sizeof(struct vr_eth);
        } else if (pkt_type == PKT_MPLS_TUNNEL_L2_CONTROL_DATA) {
            /* L2 packet with control information */
            eth = (struct vr_eth *)(va + pull_len + mpls_label_len +
                    VR_L2_CTRL_DATA_LEN);
            pull_len += mpls_label_len + VR_L2_CTRL_DATA_LEN +
                                            sizeof(struct vr_eth);
        } else if (pkt_type == PKT_MPLS_TUNNEL_L2_UCAST) {
            /* L2 packet with no control information */
            eth = (struct vr_eth *)(va + pull_len + mpls_label_len);
            pull_len += mpls_label_len + sizeof(struct vr_eth);
        } else {
            return PKT_RET_UNHANDLED;
        }

        if (frag_size < pull_len)
            return PKT_RET_SLOW_PATH;

    } else if (ip_proto == VR_IP_PROTO_UDP &&
                ntohs(gre_udp_encap) == VR_VXLAN_UDP_DST_PORT) {
        *encap_type = PKT_ENCAP_VXLAN;
        pull_len += sizeof(struct vr_vxlan);

        /* Take into consideration, the VXLAN header ethernet header */
        if (frag_size < pull_len + VR_ETHER_HLEN)
            return PKT_RET_SLOW_PATH;

        eth = (struct vr_eth *)(va + pull_len);

        pull_len += VR_ETHER_HLEN;
    } else {
        return PKT_RET_UNHANDLED;
    }

    if (eth) {

        eth_proto = eth->eth_proto;
        if (ntohs(eth_proto) == VR_ETH_PROTO_PBB) {
            pull_len += sizeof(struct vr_pbb_itag);
            if (frag_size < pull_len)
                return PKT_RET_SLOW_PATH;

            eth = (struct vr_eth *)(va + pull_len);
            pull_len += VR_ETHER_HLEN;
            if (frag_size < pull_len)
                return PKT_RET_SLOW_PATH;
            eth_proto = eth->eth_proto;
        }

        while (ntohs(eth_proto) == VR_ETH_PROTO_VLAN) {
            eth_proto = ((struct vr_vlan_hdr *)(va + pull_len))->vlan_proto;
            pull_len += sizeof(struct vr_vlan_hdr);
            if (frag_size < pull_len)
                return PKT_RET_SLOW_PATH;
        }

        if (ntohs(eth_proto) == VR_ETH_PROTO_IP) {
            iph = (struct vr_ip *)(va + pull_len);
            pull_len += sizeof(struct vr_ip);
            if (frag_size < pull_len)
                return PKT_RET_SLOW_PATH;
        } else if (ntohs(eth_proto) == VR_ETH_PROTO_IP6) {
            ip6h = (struct vr_ip6 *)(va + pull_len);
            iph = (struct vr_ip *)ip6h;
            pull_len += sizeof(struct vr_ip6);
            if (frag_size < pull_len)
                return PKT_RET_SLOW_PATH;
        } else if (ntohs(eth_proto) == VR_ETH_PROTO_ARP) {
            pull_len += sizeof(struct vr_arp);
            if (frag_size < pull_len)
                return PKT_RET_SLOW_PATH;
        }
    }

    *pull_lenp = pull_len;
    *iphp = iph;
    *ip6hp = ip6h;
    if (pkt_typep)
        *pkt_typep = pkt_type;

    return 0;
}

bool
__vr_adjust_tcp_mss(struct vr_tcp *tcph, uint16_t len_overhead, uint16_t eth_mtu, uint16_t *old_mss, uint16_t *new_mss)
{
    int opt_off = sizeof(struct vr_tcp);
    uint8_t *opt_ptr = (uint8_t *) tcph;
    uint16_t pkt_mss, max_mss;

    if ((tcph == NULL) || (!tcph->tcp_flag_syn)) {
        return false;
    }

    while (opt_off < (tcph->tcp_doff*4)) {
        switch (opt_ptr[opt_off]) {
            case VR_TCP_OPT_EOL:
                return false;

            case VR_TCP_OPT_NOP:
                opt_off++;
                continue;

            case VR_TCP_OPT_MSS:
                if ((opt_off + VR_TCP_OLEN_MSS) > (tcph->tcp_doff*4)) {
                    return false;
                }

                if (opt_ptr[opt_off+1] != VR_TCP_OLEN_MSS) {
                    return false;
                }

                pkt_mss = (opt_ptr[opt_off+2] << 8) | opt_ptr[opt_off+3];
                max_mss = eth_mtu - (len_overhead + sizeof(struct vr_tcp));

                if (pkt_mss > max_mss) {
                    *old_mss = pkt_mss;
                    *new_mss = max_mss;
                    opt_ptr[opt_off+2] = (max_mss & 0xff00) >> 8;
                    opt_ptr[opt_off+3] = max_mss & 0xff;

                    return true;
                }

                return false;

            default:

                if ((opt_off + 1) == (tcph->tcp_doff*4)) {
                    return false;
                }

                if (opt_ptr[opt_off+1]) {
                    opt_off += opt_ptr[opt_off+1];
                } else {
                    opt_off++;
                }

                continue;
        }
    }

    return false;
}


/*
 * vr_adjust_tcp_mss - adjust the TCP MSS in the given packet based on
 * vrouter physical interface MTU. If MSS was changed return true and sets
 * old_mss and new_mss args, returns false otherwise.
 */
bool
vr_adjust_tcp_mss(struct vr_tcp *tcph, uint16_t len_overhead, uint16_t *old_mss, uint16_t *new_mss)
{
    uint16_t eth_mtu = VR_INVALID_MTU;
    struct vrouter *router = vrouter_get(0);
    int i;

    if (router == NULL) {
        return false;
    }

    for (i = 0; i < VR_MAX_PHY_INF; i++) {
        if (router->vr_eth_if[i]) {
            uint16_t mtu = vif_get_mtu(router->vr_eth_if[i]);
            if (mtu < eth_mtu)
                eth_mtu = mtu;
        }
    }
    if (eth_mtu == VR_INVALID_MTU)
        return false;

    return __vr_adjust_tcp_mss(tcph, len_overhead, eth_mtu, old_mss, new_mss);
}

/*
 * calculate a 5 tuple hash for ipv4 and ipv6 packets
 * and smac, dmac and proto based hash for other packets
 */
unsigned int vr_get_pkt_hash(struct vr_packet * pkt)
{
    struct vr_tcp *tcp;
    struct vr_udp *udp;
    unsigned short sport, dport;
    int proto, flag = 0;
    struct vr_eth *eth = NULL;
    struct vr_ip *ip = NULL;
    struct vr_ip6 *ip6 = NULL;
    char *hdr = NULL;
    char key[38];
    uint32_t hash;

    if (!pkt)
        return 0;

    if (pkt->vp_type == VP_TYPE_IP6) {
        ip6 = (struct vr_ip6 *) pkt_network_header(pkt);
        hdr = (char *) ip6;
        if (vr_ip6_fragment(ip6)) {
            flag = 1;
            sport = dport = 0;
            proto = 0;
        } else
            proto = ip6->ip6_nxt;
    } else if(pkt->vp_type == VP_TYPE_IP) {
        ip = (struct vr_ip *) pkt_network_header(pkt);
        hdr = (char *) ip;
        if (vr_ip_fragment(ip)) {
            flag = 1;
            sport = dport = 0;
        }
        proto = ip->ip_proto;
    } else {
        eth = (struct vr_eth *) pkt_data(pkt);
        proto = -1;
    }

    if (flag == 0) {
        if (proto == VR_IP_PROTO_TCP) {
            if (pkt->vp_type == VP_TYPE_IP6)
                tcp = (struct vr_tcp *) (hdr + sizeof(*ip6));
            else
                tcp = (struct vr_tcp *) (hdr + ip->ip_hl*4);
            sport = ntohs(tcp->tcp_sport);
            dport = ntohs(tcp->tcp_dport);
        } else if (proto == VR_IP_PROTO_UDP) {
            if (pkt->vp_type == VP_TYPE_IP6)
                udp = (struct vr_udp *) (hdr + sizeof(*ip6));
            else
                udp = (struct vr_udp *) (hdr + ip->ip_hl*4);
            sport = ntohs(udp->udp_sport);
            dport = ntohs(udp->udp_dport);
        } else {
            sport = dport = 0;
        }
    }

    if (pkt->vp_type == VP_TYPE_IP6) {
        memcpy(key, &ip6->ip6_src, 16);
        memcpy(key+16, &ip6->ip6_dst, 16);
        memcpy(key+32, &proto, 1);
        memcpy(key+33, &sport, 2);
        memcpy(key+35, &dport, 2);
        hash = vr_hash(key, 37, 0);
    } else if (pkt->vp_type == VP_TYPE_IP) {
        memcpy(key, &ip->ip_saddr, 4);
        memcpy(key+4, &ip->ip_daddr, 4);
        memcpy(key+8, &proto, 1);
        memcpy(key+9, &sport, 2);
        memcpy(key+11, &dport, 2);
        hash = vr_hash(key, 13, 0);
    } else {
        memcpy(key, &eth->eth_smac, 6);
        memcpy(key+6, &eth->eth_dmac, 6);
        memcpy(key+12, &eth->eth_proto, 1);
        hash = vr_hash(key, 13, 0);
    }

    return hash;
}
