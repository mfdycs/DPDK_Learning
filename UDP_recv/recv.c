#include <rte_eal.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mbuf.h>

#include <stdio.h>
#include <arpa/inet.h>

#define NUM_BUFS (4096-1)

#define BURST_SIZE 128

int DPDK_PortID = 0;

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

#if 0
    struct rte_eth_dev_info dev_info;
    rte_eth_dev_info_get(DPDK_PortID, &dev_info);
#endif

    const int num_rx_queues = 1;
    const int num_tx_queues = 0;
    struct rte_eth_conf port_conf = port_conf_default;

    int ret = rte_eth_dev_configure(DPDK_PortID, num_rx_queues, num_tx_queues, &port_conf);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, ":: Cannot configure device: err = %d\n", ret);
    }

    ret = rte_eth_rx_queue_setup(DPDK_PortID, 0, 128, rte_eth_dev_socket_id(DPDK_PortID), NULL, mbuf_pool);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Could not setup RX queue\n");
    }

    ret = rte_eth_dev_start(DPDK_PortID);
    if (ret < 0) {
        rte_exit(EXIT_FAILURE, "Could not start\n");
    }
}

int main(int argc, char *argv[])
{
    if (rte_eal_init(argc, argv) < 0) {
        rte_exit(EXIT_FAILURE, "Error with EAL  init\n");
    }

    struct rte_mempool *mbuf_pool = rte_pktmbuf_pool_create("mbuf pool", NUM_BUFS, 0, 0, RTE_MBUF_DEFAULT_BUF_SIZE,
                                                            rte_socket_id());
    if (mbuf_pool == NULL) {
        rte_exit(EXIT_FAILURE, "Could not create mbuf pool\n");
    }

    ng_init_port(mbuf_pool);

    while (1) {
        struct rte_mbuf *mbufs[BURST_SIZE];

        unsigned num_recvd = rte_eth_rx_burst(DPDK_PortID, 0, mbufs, BURST_SIZE);
        if (num_recvd > BURST_SIZE) {
            rte_exit(EXIT_FAILURE, "Error receiving from eth\n");
        }

        unsigned int i = 0;
        for (i = 0; i < num_recvd; i++) {
            struct rte_ether_hdr *ethr = rte_pktmbuf_mtod(mbufs[i], struct rte_ether_hdr*);

            if (ethr->ether_type != rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4)) {
                continue;
            }

            struct rte_ipv4_hdr *iphdr = rte_pktmbuf_mtod_offset(mbufs[i], struct rte_ipv4_hdr*, sizeof(struct rte_ether_hdr));

            if (iphdr->next_proto_id == IPPROTO_UDP) {
                struct rte_udp_hdr *udphdr = (struct rte_udp_hdr*)(iphdr + 1);

                uint16_t length = ntohs(udphdr->dgram_len);
                *(char*)(udphdr + length) = '\0';

                struct in_addr addr;
                addr.s_addr = iphdr->src_addr;
                printf("src: %s:%d, ", inet_ntoa(addr), ntohs(udphdr->src_port));

                addr.s_addr = iphdr->dst_addr;
                printf("dst: %s:%d, len: %d --> %s\n", inet_ntoa(addr), ntohs(udphdr->dst_port), length, (char*)(udphdr + 1));

                rte_pktmbuf_free(mbufs[i]);
            }

        }

    }

}
