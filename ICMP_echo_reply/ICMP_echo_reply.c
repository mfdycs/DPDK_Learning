#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>
#include <rte_memcpy.h>

#include <stdio.h>
#include <arpa/inet.h>

#define NUM_BUFS (4096-1)

#define BURST_SIZE 128

int DPDK_PortID = 0;

#define ENABLE_SEND 1
#define ENABLE_ARP  1
#define ENABLE_ICMP 1

#if ENABLE_SEND

static uint32_t gSrcIp;
static uint32_t gDstIp;

static uint8_t gSrcMac[RTE_ETHER_ADDR_LEN];
static uint8_t gDstMac[RTE_ETHER_ADDR_LEN];

static uint16_t gSrcPort;
static uint16_t gDstPort;

#endif

#if ENABLE_ARP

#define MAKE_IPV4_ADDR(a, b, c, d) (a + (b<<8) + (c<<16) + (d<<24))
static uint32_t gLocalIp = MAKE_IPV4_ADDR(192, 168, 81, 128);

#endif

static const struct rte_eth_conf port_conf_default = {
        .rxmode = {
                .max_rx_pkt_len = RTE_ETHER_MAX_LEN,
        },
};

static void ng_init_port(struct rte_mempool *mbuf_pool)
{
    uint16_t nb_sys_ports = rte_eth_dev_count_avail();
    if (nb_sys_ports == 0) {
        rte_exit(EXIT_FAILURE, "No Supported eth found\n");
    }

    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(DPDK_PortID, &dev_info);

    const int num_rx_queues = 1;
    const int num_tx_queues = 1;
    struct rte_eth_conf port_conf = port_conf_default;

    int ret = rte_eth_dev_configure(DPDK_PortID, num_rx_queues, num_tx_queues, &port_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, ":: Cannot configure device: err = %d\n", ret);
    }

    // rte_eth_rx_queue_setup(port_id, rx_queue_id, nb_rx_desc, socket_id, rx_conf, mb_pool);
    ret = rte_eth_rx_queue_setup(DPDK_PortID, 0, 128, rte_eth_dev_socket_id(DPDK_PortID), NULL, mbuf_pool);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

#if ENABLE_SEND
    struct rte_eth_txconf txq_conf = dev_info.default_txconf;
    txq_conf.offloads = port_conf.rxmode.offloads;

    // rte_eth_tx_queue_setup(port_id, tx_queue_id, nb_rx_desc, socket_id, tx_conf);
    ret = rte_eth_tx_queue_setup(DPDK_PortID, 0, 128, rte_eth_dev_socket_id(DPDK_PortID), &txq_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup TX queue\n");
    }
#endif

    ret = rte_eth_dev_start(DPDK_PortID);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }
}

// encode udp pkt
static int ng_encode_udp_pkt(uint8_t *msg, unsigned char* data, uint16_t total_len)
{
    // 1. ethhdr
    struct rte_ether_hdr* eth = (struct rte_ether_hdr*)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4);

    // 2. iphdr
    struct rte_ipv4_hdr* ip = (struct rte_ipv4_hdr*)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x54; 
    ip->type_of_service = 0;
    ip->total_length = htons(total_len - sizeof(struct rte_ether_hdr));
    ip->packet_id = 0;
    ip->fragment_offset = 0;
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_UDP;
    ip->src_addr = gSrcIp;
    ip->dst_addr = gDstIp;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // 3. udphdr
    struct rte_udp_hdr* udp = (struct rte_udp_hdr*)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr));
    udp->src_port = gSrcPort;
    udp->dst_port = gDstPort;
    uint16_t udplen = total_len - sizeof(struct rte_ether_hdr) - sizeof(struct rte_ipv4_hdr);
    udp->dgram_len = htons(udplen);

    rte_memcpy((uint8_t*)(udp + 1), data, udplen);

    udp->dgram_cksum = 0;
    udp->dgram_cksum = rte_ipv4_udptcp_cksum(ip, udp);

    // 4. print
    struct in_addr addr;
    addr.s_addr = gSrcIp;
    printf(" --> src: %s:%d, ", inet_ntoa(addr), ntohs(gSrcPort));

    addr.s_addr = gDstIp;
    printf("dst: %s:%d\n", inet_ntoa(addr), ntohs(gDstPort));

    return 0;
}

static struct rte_mbuf* ng_send_udp(struct rte_mempool *mbuf_pool, unsigned char* data, uint16_t length)
{
    const unsigned total_len = length + 42;

    struct rte_mbuf* mbuf =  rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }
    mbuf->pkt_len = total_len;
    mbuf->data_len = total_len;

    uint8_t *pktdata = rte_pktmbuf_mtod(mbuf, uint8_t*);

    ng_encode_udp_pkt(pktdata, data, total_len);

    return mbuf;
}

#if ENABLE_ARP

static int ng_encode_arp_pkt(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip)
{
    // 1 ethhdr
    struct rte_ether_hdr *eth = (struct rte_ether_hdr *)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_ARP);

    // 2 arp
    struct rte_arp_hdr *arp = (struct rte_arp_hdr *)(eth + 1);
    arp->arp_hardware = htons(1);
    arp->arp_protocol = htons(RTE_ETHER_TYPE_IPV4);
    arp->arp_hlen = RTE_ETHER_ADDR_LEN;
    arp->arp_plen = sizeof(uint32_t); 
    arp->arp_opcode = htons(2);

    rte_memcpy(arp->arp_data.arp_sha.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy( arp->arp_data.arp_tha.addr_bytes, dst_mac, RTE_ETHER_ADDR_LEN);

    arp->arp_data.arp_sip = sip;
    arp->arp_data.arp_tip = dip;

    return 0;
}

static struct rte_mbuf* ng_send_arp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac, uint32_t sip, uint32_t dip)
{
    // len(arp:42) = len(eth:14) + len(arp:28)
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_arp_pkt(pkt_data, dst_mac, sip, dip);

    return mbuf;
}

#endif

#if ENABLE_ICMP

static uint16_t icmp_checksum(uint16_t *addr, int count) {

    register long sum = 0;

    while (count > 1) {
        sum += *(unsigned short*)addr++;
        count -= 2;
    }

    if (count > 0) {
        sum += *(unsigned char *)addr;
    }

    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

static int ng_encode_icmp_pkt(uint8_t *msg, uint8_t *dst_mac, uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb)
{
    // 1. ethhdr
    struct rte_ether_hdr* eth = (struct rte_ether_hdr*)msg;
    rte_memcpy(eth->s_addr.addr_bytes, gSrcMac, RTE_ETHER_ADDR_LEN);
    rte_memcpy(eth->d_addr.addr_bytes, gDstMac, RTE_ETHER_ADDR_LEN);
    eth->ether_type = htons(RTE_ETHER_TYPE_IPV4); // 协议类型

    // 2. iphdr
    struct rte_ipv4_hdr* ip = (struct rte_ipv4_hdr*)(msg + sizeof(struct rte_ether_hdr));
    ip->version_ihl = 0x54; // 版本+首部长度信息, 网络字节序
    ip->type_of_service = 0;
    ip->total_length = htons(sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr));
    ip->packet_id = 0; // 16位位标识
    ip->fragment_offset = 0; // 3位标识+13位片位移
    ip->time_to_live = 64;
    ip->next_proto_id = IPPROTO_ICMP;
    ip->src_addr = gSrcIp;
    ip->dst_addr = gDstIp;

    ip->hdr_checksum = 0;
    ip->hdr_checksum = rte_ipv4_cksum(ip);

    // 3. icmphdr
    struct rte_icmp_hdr* icmp = (struct rte_icmp_hdr*)(msg + sizeof(struct rte_ether_hdr) + sizeof(struct rte_icmp_hdr));
    icmp->icmp_type = RTE_IP_ICMP_ECHO_REPLY;
    icmp->icmp_code = 0; // code:0 回应请求

    icmp->icmp_ident = id;
    icmp->icmp_seq_nb = seqnb;

    // icmp->icmp_cksum = rte_ipv4_cksum(ip, icmp); // 错误
    icmp->icmp_cksum = icmp_checksum((uint16_t*)icmp, sizeof(struct rte_icmp_hdr));
}

static struct rte_mbuf *ng_send_icmp(struct rte_mempool *mbuf_pool, uint8_t *dst_mac,
                                     uint32_t sip, uint32_t dip, uint16_t id, uint16_t seqnb)
{
    const unsigned total_length = sizeof(struct rte_ether_hdr) + sizeof(struct rte_ipv4_hdr) + sizeof(struct rte_icmp_hdr);

    struct rte_mbuf *mbuf = rte_pktmbuf_alloc(mbuf_pool);
    if (!mbuf) {
        rte_exit(EXIT_FAILURE, "rte_pktmbuf_alloc\n");
    }

    mbuf->pkt_len = total_length;
    mbuf->data_len = total_length;

    uint8_t *pkt_data = rte_pktmbuf_mtod(mbuf, uint8_t *);
    ng_encode_icmp_pkt(pkt_data, dst_mac, sip, dip, id, seqnb);

    return mbuf;
}

#endif

int main(int argc, char *argv[])
{
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL init\n");
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_BUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                                            rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    ng_init_port(mbuf_pool);

    rte_eth_macaddr_get(DPDK_PortID, (struct rte_ether_addr *)gSrcMac);

    while (1) {
        struct rte_mbuf *mbufs[BURST_SIZE];

        unsigned num_recvd = rte_eth_rx_burst(DPDK_PortID, 0, mbufs, BURST_SIZE);
        if (num_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        }

        unsigned int i = 0;
        for (i = 0; i < num_recvd; i++) {
            struct rte_ether_hdr *ethr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

#if ENABLE_ARP
            if (ethr->ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP)) {
                struct rte_arp_hdr *arp_hdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_arp_hdr*, sizeof(struct rte_ether_hdr));

                struct in_addr addr;
                addr.s_addr = arp_hdr->arp_data.arp_tip;
                printf("arp ---> src: %s ", inet_ntoa(addr));

                addr.s_addr = gLocalIp;
                printf("arp ---> local: %s \n", inet_ntoa(addr));

                if (arp_hdr->arp_data.arp_tip == gLocalIp) {
                    struct rte_mbuf *arpbuf = ng_send_arp(mbuf_pool, arp_hdr->arp_data.arp_sha.addr_bytes,
                                                          arp_hdr->arp_data.arp_tip, arp_hdr->arp_data.arp_sip);

                    rte_eth_tx_burst(DPDK_PortID, 0, &arpbuf, 1);
                    rte_pktmbuf_free(arpbuf);
                    rte_pktmbuf_free(mbufs[i]);
                }

                continue;
            }
#endif

            // 不是ipv4协议跳过
            if (ethr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));

            // UDP协议数据
            if (iphdr->next_proto_id == IPPROTO_UDP) {
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr*)(iphdr + 1);

#if ENABLE_SEND
                rte_memcpy(gDstMac, ethr->s_addr.addr_bytes, RTE_ETHER_ADDR_LEN);

                rte_memcpy(&gSrcIp, &iphdr->dst_addr, sizeof(uint32_t));
                rte_memcpy(&gSrcIp, &iphdr->src_addr, sizeof(uint32_t));

                rte_memcpy(&gSrcPort, &udphdr->src_port, sizeof(uint16_t));
                rte_memcpy(&gDstPort, &udphdr->dst_port, sizeof(uint16_t));
#endif

                uint16_t length = ntohs(udphdr->dgram_len);
                *(char*)(udphdr + length) = '\0';

                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

                addr.s_addr = iphdr->dst_addr;
                printf("dst: %s:%d, len: %d --> %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), length, (char*)(udphdr + 1));

#if ENABLE_SEND
                struct rte_mbuf* txbuf = ng_send_udp(mbuf_pool, (uint8_t *)(udphdr+1), length);
                //rte_eth_tx_burst(port_id, queue_id, tx_pkts, num of tx_pkts);
                rte_eth_tx_burst(DPDK_PortID, 0, &txbuf, 1);
                rte_pktmbuf_free(txbuf);
#endif

                rte_pktmbuf_free(mbufs[i]);
            }

            // ICMP
#if ENABLE_ICMP
            if (iphdr->next_proto_id == IPPROTO_ICMP) {
                struct rte_icmp_hdr *icmphdr = (struct rte_icmp_hdr *)(iphdr + 1);

                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("icmp ---> src: %s ", inet_ntoa(addr));

                // 如果是ICMP请求: 8 0
                if (icmphdr->icmp_type == RTE_IP_ICMP_ECHO_REQUEST) {

                    addr.s_addr = iphdr->dst_addr;
                    printf("icmp ---> local: %s , type : %d\n", inet_ntoa(addr), icmphdr->icmp_type);

                    struct rte_mbuf *txbuf = ng_send_icmp(mbuf_pool, ethr->s_addr.addr_bytes, iphdr->dst_addr,
                            iphdr->src_addr, icmphdr->icmp_ident, icmphdr->icmp_seq_nb);

                    rte_eth_tx_burst(DPDK_PortID, 0, &txbuf, 1);
                    rte_pktmbuf_free(txbuf);
                    rte_pktmbuf_free(mbufs[i]);
                }
            }
#endif

        }

    }

}

