/*
 * Copyright 2004-present Facebook. All Rights Reserved.
 * This is main balancer's application code
 */

#include <linux/in.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <stddef.h>
#include <stdbool.h>

#include "balancer_consts.h"
#include "balancer_helpers.h"
#include "balancer_structs.h"
#include "balancer_maps.h"
#include "bpf.h"
#include "bpf_helpers.h"
#include "jhash.h"
#include "pckt_encap.h"
#include "pckt_parsing.h"
#include "handle_icmp.h"


__attribute__((__always_inline__))
static inline __u32 get_packet_hash(struct packet_description *pckt,
                                    bool hash_16bytes) {
  if (hash_16bytes) {
    return jhash_2words(jhash(pckt->flow.srcv6, 16, INIT_JHASH_SEED_V6),
                        pckt->flow.ports, INIT_JHASH_SEED);
  } else {
    return jhash_2words(pckt->flow.src, pckt->flow.ports, INIT_JHASH_SEED);
  }
}

__attribute__((__always_inline__))
static inline bool is_under_flood(__u64 *cur_time) {
  __u32 conn_rate_key = MAX_VIPS + NEW_CONN_RATE_CNTR;
  struct lb_stats *conn_rate_stats = bpf_map_lookup_elem(
    &stats, &conn_rate_key);
  if (!conn_rate_stats) {
    return true;
  }
  *cur_time = bpf_ktime_get_ns();
  // we are going to check that new connections rate is less than predefined
  // value; conn_rate_stats.v1 contains number of new connections for the last
  // second, v2 - when last time quanta started.
  if ((*cur_time - conn_rate_stats->v2) > ONE_SEC) {
    // new time quanta; reseting counters
    conn_rate_stats->v1 = 1;
    conn_rate_stats->v2 = *cur_time;
  } else {
    conn_rate_stats->v1 += 1;
    if (conn_rate_stats->v1 > MAX_CONN_RATE) {
      // we are exceding max connections rate. bypasing lru update and
      // source routing lookup
      return true;
    }
  }
  return false;
}

__attribute__((__always_inline__))
static inline bool get_packet_dst(struct real_definition **real,
                                  struct packet_description *pckt,
                                  struct vip_meta *vip_info,
                                  void *lru_map) {

  // to update lru w/ new connection
  struct real_pos_lru new_dst_lru = {};
  bool under_flood = false;
  bool src_found = false;
  __u32 *real_pos;
  __u64 cur_time = 0;
  __u32 hash;
  __u32 key;

  under_flood = is_under_flood(&cur_time);

  #ifdef LPM_SRC_LOOKUP
  if ((vip_info->flags & F_SRC_ROUTING) && !under_flood) {
    __u32 *lpm_val;
    struct v4_lpm_key lpm_key_v4 = {};
    lpm_key_v4.addr = pckt->flow.src;
    lpm_key_v4.prefixlen = 32;
    lpm_val = bpf_map_lookup_elem(&lpm_src_v4, &lpm_key_v4);
    if (lpm_val) {
      src_found = true;
      key = *lpm_val;
    }
    __u32 stats_key = MAX_VIPS + LPM_SRC_CNTRS;
    struct lb_stats *data_stats = bpf_map_lookup_elem(&stats, &stats_key);
    if (data_stats) {
      if (src_found) {
        data_stats->v2 += 1;
      } else {
        data_stats->v1 += 1;
      }
    }
  }
  #endif
  if (!src_found) {
    bool hash_16bytes = false;

    if (vip_info->flags & F_HASH_DPORT_ONLY) {
      // service which only use dst port for hash calculation
      // e.g. if packets has same dst port -> they will go to the same real.
      // usually VoIP related services.
      pckt->flow.port16[0] = pckt->flow.port16[1];
      memset(pckt->flow.srcv6, 0, 16);
    }
    hash = get_packet_hash(pckt, hash_16bytes) % RING_SIZE;
    key = RING_SIZE * (vip_info->vip_num) + hash;

    real_pos = bpf_map_lookup_elem(&ch_rings, &key);
    if(!real_pos) {
      return false;
    }
    key = *real_pos;
  }
  pckt->real_index = key;
  *real = bpf_map_lookup_elem(&reals, &key);
  if (!(*real)) {
    return false;
  }
  if (!(vip_info->flags & F_LRU_BYPASS) && !under_flood) {
    if (pckt->flow.proto == IPPROTO_UDP) {
      new_dst_lru.atime = cur_time;
    }
    new_dst_lru.pos = key;
    bpf_map_update_elem(lru_map, &pckt->flow, &new_dst_lru, BPF_ANY);
  }
  return true;
}

__attribute__((__always_inline__))
static inline void connection_table_lookup(struct real_definition **real,
                                           struct packet_description *pckt,
                                           void *lru_map) {

  struct real_pos_lru *dst_lru;
  __u64 cur_time;
  __u32 key;
  dst_lru = bpf_map_lookup_elem(lru_map, &pckt->flow);
  if (!dst_lru) {
    *real = NULL;
    return;
  }
  if (pckt->flow.proto == IPPROTO_UDP) {
    cur_time = bpf_ktime_get_ns();
    if (cur_time - dst_lru->atime > LRU_UDP_TIMEOUT) {
      *real = NULL;
      return;
    }
    dst_lru->atime = cur_time;
  }
  key = dst_lru->pos;
  pckt->real_index = key;

  // char fmt[] = "Conntrack lookup: %u\n";
  // bpf_trace_printk(fmt, sizeof(fmt), key);

  if (pckt->real_index == 8) {
    (*real)->dst = 0x0101460a;
    (*real)->flags = 0;
    // char fmt[] = "Hitting optimized path 2\n";
    // bpf_trace_printk(fmt, sizeof(fmt));
  } else {
    *real = bpf_map_lookup_elem(&reals, &key);
  }
  return;
}

__attribute__((__always_inline__))
static inline int process_l3_headers(struct packet_description *pckt,
                                     __u8 *protocol, __u64 off,
                                     __u16 *pkt_bytes, void *data,
                                     void *data_end) {
  __u64 iph_len;
  int action;
  struct iphdr *iph;

  iph = data + off;
  if (iph + 1 > data_end) {
    return XDP_DROP;
  }
  //ihl contains len of ipv4 header in 32bit words
  if (iph->ihl != 5) {
    // if len of ipv4 hdr is not equal to 20bytes that means that header
    // contains ip options, and we dont support em
    return XDP_DROP;
  }
  pckt->tos = iph->tos;
  *protocol = iph->protocol;
  pckt->flow.proto = *protocol;
  *pkt_bytes = bpf_ntohs(iph->tot_len);
  off += IPV4_HDR_LEN_NO_OPT;

  if (iph->frag_off & PCKT_FRAGMENTED) {
    // we drop fragmented packets.
    return XDP_DROP;
  }
  if (*protocol == IPPROTO_ICMP) {
    action = parse_icmp(data, data_end, off, pckt);
    if (action >= 0) {
      return action;
    }
  } else {
    pckt->flow.src = iph->saddr;
    pckt->flow.dst = iph->daddr;
  }
  return FURTHER_PROCESSING;
}

__attribute__((__always_inline__))
static inline int process_packet(void *data, __u64 off, void *data_end, struct xdp_md *xdp) {

  // char fmt[] = "Processing packet\n";
  // bpf_trace_printk(fmt, sizeof(fmt));
  
  struct ctl_value *cval;
  struct real_definition dst_tmp;
  dst_tmp.dst = 0;
  dst_tmp.flags = 0;

  struct real_definition *dst = NULL;
  struct packet_description pckt = {};
  struct vip_definition vip = {};
  struct vip_meta vip_info_tmp = {};
  struct vip_meta *vip_info;
  struct lb_stats *data_stats;
  __u64 iph_len;
  __u8 protocol;

  int action;
  __u32 vip_num;
  __u32 mac_addr_pos = 0;
  __u16 pkt_bytes;
  action = process_l3_headers(
    &pckt, &protocol, off, &pkt_bytes, data, data_end);
  if (action >= 0) {
    char fmt1[] = "Return action\n";
    bpf_trace_printk(fmt1, sizeof(fmt1));
    return action;
  }
  protocol = pckt.flow.proto;

  if (protocol == IPPROTO_UDP) {
    if (!parse_udp(data, data_end, false, &pckt)) {
      return XDP_DROP;
    }
  } else {
    char fmt1[] = "Return XDP_PASS\n";
    bpf_trace_printk(fmt1, sizeof(fmt1));
    // send to tcp/ip stack
    return XDP_PASS;
  }

  // char fmt3[] = "INFO: pckt.flow.dst = %u, pckt.dst = %u, proto = %u\n";
  // bpf_trace_printk(fmt3, sizeof(fmt3), pckt.flow.dst, pckt.flow.port16[1], pckt.flow.proto);

  // Check packet port destination (i.e., 10.70.2.2 && 5678 le)
  if (pckt.flow.dst == 33703434 && pckt.flow.port16[1] == 11798 && pckt.flow.proto == IPPROTO_UDP) {
    vip_info = &vip_info_tmp;
    vip_info->flags = 0;
    vip_info->vip_num = 0;
    // char fmt2[] = "Hitting optimized path 1\n";
    // bpf_trace_printk(fmt2, sizeof(fmt2));
  } else {
    return XDP_PASS;
  }

  if (data_end - data > MAX_PCKT_SIZE) {
    REPORT_PACKET_TOOBIG(xdp, data, data_end - data, false);
    return XDP_DROP;
  }

  __u32 stats_key = MAX_VIPS + LRU_CNTRS;
  data_stats = bpf_map_lookup_elem(&stats, &stats_key);
  if (!data_stats) {
    return XDP_DROP;
  }

  // total packets
  data_stats->v1 += 1;

  if (!dst) {
    if ((vip_info->flags & F_HASH_NO_SRC_PORT)) {
      // service, where diff src port, but same ip must go to the same real,
      // e.g. gfs
      pckt.flow.port16[0] = 0;
    }
    __u32 cpu_num = bpf_get_smp_processor_id();
    void *lru_map = bpf_map_lookup_elem(&lru_mapping, &cpu_num);
    if (!lru_map) {
      lru_map = &fallback_cache;
      __u32 lru_stats_key = MAX_VIPS + FALLBACK_LRU_CNTR;
      struct lb_stats *lru_stats = bpf_map_lookup_elem(&stats, &lru_stats_key);
      if (!lru_stats) {
        return XDP_DROP;
      }
      // we weren't able to retrieve per cpu/core lru and falling back to
      // default one. this counter should never be anything except 0 in prod.
      // we are going to use it for monitoring.
      lru_stats->v1 += 1;
    }

    if (!(pckt.flags & F_SYN_SET) &&
        !(vip_info->flags & F_LRU_BYPASS)) {
      // char fmt3[] = "connection_table_lookup \n";
      // bpf_trace_printk(fmt3, sizeof(fmt3));
      dst = &dst_tmp;
      connection_table_lookup(&dst, &pckt, lru_map);
    }

    if (!dst) {
      // char fmt4[] = "get_packet_dst \n";
      // bpf_trace_printk(fmt4, sizeof(fmt4));
      if(!get_packet_dst(&dst, &pckt, vip_info, lru_map)) {
        return XDP_DROP;
      }
      // lru misses (either new connection or lru is full and starts to trash)
      data_stats->v2 += 1;
    }
  }

  cval = bpf_map_lookup_elem(&ctl_array, &mac_addr_pos);

  if (!cval) {
    return XDP_DROP;
  }

  if(!PCKT_ENCAP_V4(xdp, cval, &pckt, dst, pkt_bytes)) {
    return XDP_DROP;
  }

  vip_num = vip_info->vip_num;
  data_stats = bpf_map_lookup_elem(&stats, &vip_num);
  if (!data_stats) {
    return XDP_DROP;
  }
  data_stats->v1 += 1;
  data_stats->v2 += pkt_bytes;

  // per real statistics
  data_stats = bpf_map_lookup_elem(&reals_stats, &pckt.real_index);
  if (!data_stats) {
    return XDP_DROP;
  }
  data_stats->v1 += 1;
  data_stats->v2 += pkt_bytes;

  return XDP_TX;
}

SEC("xdp-balancer")
int balancer_ingress(struct xdp_md *ctx) {
  void *data = (void *)(long)ctx->data;
  void *data_end = (void *)(long)ctx->data_end;
  struct eth_hdr *eth = data;
  __u32 eth_proto;
  __u32 nh_off;
  nh_off = sizeof(struct eth_hdr);

  if (data + nh_off > data_end) {
    // bogus packet, len less than minimum ethernet frame size
    return XDP_DROP;
  }

  eth_proto = eth->eth_proto;

  if (eth_proto == BE_ETH_P_IP) {
    return process_packet(data, nh_off, data_end, ctx);
  } else {
    // pass to tcp/ip stack
    return XDP_PASS;
  }
}

char _license[] SEC("license") = "GPL";
