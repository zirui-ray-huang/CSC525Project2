/**********************************************************************
 * file:  sr_router.c 
 * date:  Mon Feb 18 12:50:42 PST 2002  
 * Contact: casado@stanford.edu 
 *
 * Description:
 * 
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing. 11
 * 90904102
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include "netinet/if_ether.h"
#include "arpa/inet.h"


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_pwospf.h"


struct icmp_hdr
{
    u_int8_t type;                /* message type */
    u_int8_t code;                /* type sub-code */
    u_int16_t checksum;
    union
    {
        struct
        {
            u_int16_t        id;
            u_int16_t        sequence;
        } echo;                        /* echo datagram */
        u_int32_t        gateway;        /* gateway address */
        struct
        {
            u_int16_t        __unused;
            u_int16_t        mtu;
        } frag;                        /* path mtu discovery */
    } un;
}__attribute__((packed));


struct sr_arp_cache_node{
    uint32_t ip_addr;
    uint8_t mac_addr[ETHER_ADDR_LEN];
    struct sr_arp_cache_node *next;
    time_t timeout;
};

struct sr_arp_cache{
    struct sr_arp_cache_node *first;
    struct sr_arp_cache_node *last;
};


struct sr_packet_queue_node{
    uint8_t *packet;
    unsigned len;
    struct sr_packet_queue_node *next;
};
struct sr_packet_queue{
    struct sr_packet_queue_node *first;
    struct sr_packet_queue_node *last;
};


struct sr_arp_queue_node{
    uint32_t ip_addr;
    struct sr_if *itface;
    struct sr_packet_queue packet_queue;
    time_t lasttime;
    struct sr_arp_queue_node *next;
};

struct sr_arp_queue{
    struct sr_arp_queue_node *first;
    struct sr_arp_queue_node *last;
};


static struct sr_arp_cache arp_cache = {0, 0};
static struct sr_arp_queue arp_queue = {0, 0};

/*--------------------------------------------------------------------- 
 * Method: sr_init(void)
 * Scope:  Global
 *
 * Initialize the routing subsystem
 * 
 *---------------------------------------------------------------------*/

void sr_init(struct sr_instance* sr) 
{
    /* REQUIRES */
    assert(sr);

    /* Add initialization code here! */

} /* -- sr_init -- */


/*---------------------------------------------------------------------
 * Method:
 *
 * https://gist.github.com/david-hoze/0c7021434796997a4ca42d7731a7073a
 *---------------------------------------------------------------------*/

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static uint16_t compute_checksum(uint16_t *addr, unsigned int count) {
    register uint32_t sum = 0;
    while (count > 1) {
        sum += * addr++;
        count -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(count > 0) {
        sum += ((*addr)&htons(0xFF00));
    }
    //Fold sum to 16 bits: add carrier to result
    while (sum>>16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    //one's complement
    sum = ~sum;
    return ((uint16_t)sum);
}

static void construct_icmp_reply(uint8_t * packet){

    struct sr_ethernet_hdr *ethernet_hdr = (struct sr_ethernet_hdr*) packet;
    struct ip *ip_hdr = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));
    struct icmp_hdr *icmp_hdr = (struct icmp_hdr*) (packet + sizeof(struct sr_ethernet_hdr) + ip_hdr->ip_hl * 4);

    // Swap ethernet addresses
    uint8_t ether_addr_temp[ETHER_ADDR_LEN];
    memcpy(ether_addr_temp, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_shost, ethernet_hdr->ether_dhost, ETHER_ADDR_LEN);
    memcpy(ethernet_hdr->ether_dhost, ether_addr_temp, ETHER_ADDR_LEN);

    // Swap ip addresses
    struct in_addr temp = ip_hdr->ip_src;
    ip_hdr->ip_src = ip_hdr->ip_dst;
    ip_hdr->ip_dst = temp;

    // Changes to icmp_type, icmp checksum, and ip checksum
    icmp_hdr->type = ICMP_ECHOREPLY;
    icmp_hdr->checksum = 0;
    icmp_hdr->checksum = compute_checksum((uint16_t*)icmp_hdr,ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4));
    ip_hdr->ip_sum = 0;
    ip_hdr->ip_sum= compute_checksum((uint16_t*)ip_hdr,ip_hdr->ip_hl*4);
}


static struct sr_arp_cache_node* ether_addr_in_arp_cache(uint32_t ip_addr){
    struct sr_arp_cache_node *cur = arp_cache.first;
    while (cur && (cur->ip_addr != ip_addr)) cur = cur->next;
    if (cur) return cur;
    return 0;
}

static struct sr_arp_queue_node* ip_addr_in_arp_queue(uint32_t ip_addr){
    if (!arp_queue.first) return 0;
    struct sr_arp_queue_node* cur = arp_queue.first;
    while (cur && cur->ip_addr != ip_addr) cur = cur->next;
    if (cur) return cur;
    return 0;
}

static void print_ip_address(uint32_t ip_address){
    const int NBYTES = 4;
    uint8_t octet[NBYTES];
    int x;
    char *ipAddressFinal[16];
    for(int i = 0 ; i < NBYTES ; i++)
    {
        octet[i] = ip_address >> (i * 8);
    }
    printf("%d.%d.%d.%d\n", octet[0], octet[1], octet[2], octet[3]);
}

/*---------------------------------------------------------------------
 * Method: sr_handlepacket(uint8_t* p,char* interface)
 * Scope:  Global
 *
 * This method is called each time the router receives a packet on the
 * interface.  The packet buffer, the packet length and the receiving
 * interface are passed in as parameters. The packet is complete with
 * ethernet headers.
 *
 * Note: Both the packet buffer and the character's memory are handled
 * by sr_vns_comm.c that means do NOT delete either.  Make a copy of the
 * packet instead if you intend to keep it around beyond the scope of
 * the method call.
 *
 *---------------------------------------------------------------------*/

void sr_handlepacket(struct sr_instance* sr, 
        uint8_t * packet/* lent */,
        unsigned int len,
        char* interface/* lent */)
{
    /* REQUIRES */
    assert(sr);
    assert(packet);
    assert(interface);

    printf("*** -> Received packet of length %d \n",len);

    struct sr_ethernet_hdr *ethernet_hdr = (struct sr_ethernet_hdr*) packet;

    uint16_t packet_type = ntohs (ethernet_hdr -> ether_type);

    /* If the incoming packet is an IP packet */
    if (packet_type == ETHERTYPE_IP){
        printf("[Debug] This is an IP packet.\n");

        struct ip *ip_hdr = (struct ip*) (packet + sizeof(struct sr_ethernet_hdr));

        /* 1. If the destination IP is one of the router’s */
        struct sr_if *if_match = sr->if_list;
        while (if_match && (ip_hdr->ip_dst).s_addr != if_match->ip) if_match = if_match->next;

        if (if_match)
        {
            printf("[Debug] This packet is destined to the router.\n");
            /* 1.a If the packet is an ICMP echo request, the router should respond with an ICMP echo reply. */
            if (ip_hdr->ip_p == IPPROTO_ICMP) {
                struct icmp_hdr *icmp_hdr = (struct icmp_hdr*) (packet + sizeof(struct sr_ethernet_hdr) + ip_hdr->ip_hl*4);
                if (icmp_hdr->type == ICMP_ECHO){
                    printf("This packet is an ICMP echo request.\n");
                    uint16_t icmp_hdr_cksum = icmp_hdr->checksum;
                    icmp_hdr->checksum = 0;
                    if(compute_checksum((uint16_t*) icmp_hdr, ntohs(ip_hdr->ip_len) - (ip_hdr->ip_hl * 4)) != icmp_hdr_cksum)
                    {
                        printf("Error in checking ICMP checksum. The router drops this packet.\n");
                        return;
                    }else printf("[Debug] ICMP checksum correct.\n");
                    construct_icmp_reply(packet);
                    printf("The router constructs the ICMP echo reply.\n");
                    if(sr_send_packet(sr, (uint8_t*) packet, len, interface)){
                        printf("Error in sending ICMP echo reply.\n");
                    }else printf("Success in sending ICMP echo reply.\n");
                }else{
                    printf("[Debug] ICMP type is not ICMP_ECHO.\n");
                }
            }
            /* 1.b Otherwise discard the packet. */
            return;
        }

        printf("[Debug] This packet is NOT destined to the router.\n");
        /* 2. Decrement TTL by 1. */
        printf("[Debug] Decrease TTL by 1.\n");
        ip_hdr->ip_ttl -= 1;
        /* 2.a If the result is 0, discard the packet.*/
        if (ip_hdr->ip_ttl == 0) {
            printf("[Debug] TTL = 0. Drops the packet.\n");
            return;
        }
        printf("[Debug] TTL > 0. Continue.\n");
        /* 2.b Otherwise, calculate header checksum and save the result to the checksum field. */
        printf("[Debug] Calculate header checksum.\n");
        ip_hdr->ip_sum = 0;
        ip_hdr->ip_sum = compute_checksum((uint16_t *) ip_hdr, ip_hdr->ip_hl * 4);

        /* 3. Use the IP destination address to look up the routing table,
         * find the matching entry to be used for packet forwarding.*/
        printf("[Debug] Look up the routing table.\n");

        struct sr_rt* temp = sr->routing_table;
        struct sr_rt* default_route = NULL;
        struct sr_rt* route = NULL;
        struct sr_rt* rt_match;
        while(temp != NULL)
        {
            if (temp->dest.s_addr == 0) default_route = temp;
            else
            {
                if (route == NULL)
                {
                    if ((temp->dest.s_addr & temp->mask.s_addr) == (ip_hdr->ip_dst.s_addr & temp->mask.s_addr)) route = temp;
                }
            }
            temp = temp->next;
        }

        if (route != NULL) rt_match = route;
        else rt_match = default_route;

        /* 4. Based on the matching entry, send the packet to the nexthop via the interface*/
        /* If nexthop is 0.0.0.0, it means the nexthop node is the final destination of the packet.
         * Therefore the destination address in the IP header should be used as the nexthop,
         * and the packet should be forwarded to it. */
        in_addr_t nexthop_ip_addr;
        if (rt_match->gw.s_addr == 0) {
            nexthop_ip_addr = ip_hdr->ip_dst.s_addr;
            printf("[Debug] The nexthop node is the final destination: ");
        }
        else {
            nexthop_ip_addr = (rt_match->gw).s_addr;
            printf("[Debug] The nexthop node is NOT the final destination: ");
        }
        print_ip_address(nexthop_ip_addr);

        /* a. Obtain nexthop’s Ethernet address from ARP cache */
        printf("[Debug] Obtaining nexthop's Ethernet address from ARP cache.\n");
        struct sr_arp_cache_node *arp_cache_node_match = ether_addr_in_arp_cache(nexthop_ip_addr);

        time_t raw_time;
        /* If the Ethernet address is in the cache */
        if (arp_cache_node_match && raw_time <= arp_cache_node_match->timeout){
            printf("[Debug] Next hop's Ethernet address is in the cache.\n");
            struct sr_if* out_if = sr_get_interface(sr, rt_match->interface);
            memcpy(ethernet_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
            memcpy(ethernet_hdr->ether_dhost, arp_cache_node_match->mac_addr, ETHER_ADDR_LEN);
            ip_hdr->ip_sum = 0;
            ip_hdr->ip_sum= compute_checksum((uint16_t*)ip_hdr,ip_hdr->ip_hl * 4);
            if (sr_send_packet(sr, (uint8_t*)packet, len, out_if->name)) printf("Error in sending IP packet with cached ethernet address.\n");
            else printf("[Debug] Success in sending IP packet with cached ethernet address.\n");
        }else{
            if(!arp_cache_node_match) printf("[Debug] Next hop's Ethernet address is NOT in the cache.\n");
            else printf("[Debug] Time out.\n");
            /* Or ARP request if it’s not in the cache. */
            struct sr_arp_queue_node* arp_queue_node_match = ip_addr_in_arp_queue(nexthop_ip_addr);
            printf("[Debug] Test.\n");
            /* If the ARP request for the same IP address was sent before */
            if (arp_queue_node_match){
                printf("[Debug] The ARP request for the same ip address was sent before.\n");
                time_t raw_time;
                if (time(&raw_time) > arp_queue_node_match->lasttime + 5){
                    printf("[Debug] Certain time has passed since last ARP request. Resend an ARP request.\n");
                    /* Send ARP request */
                    uint8_t *new_arp_packet = (uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
                    struct sr_arphdr *new_arp_hdr = (struct sr_arphdr*) (new_arp_packet + sizeof(struct sr_ethernet_hdr));
                    new_arp_hdr ->ar_hln = 6;
                    new_arp_hdr ->ar_hrd = htons(1);
                    new_arp_hdr ->ar_op  = htons(ARP_REQUEST);
                    new_arp_hdr ->ar_pln = 4;
                    new_arp_hdr ->ar_pro = htons(ETHERTYPE_IP);
                    memcpy(new_arp_hdr->ar_sha, arp_queue_node_match->itface->addr, ETHER_ADDR_LEN);
                    new_arp_hdr ->ar_sip = arp_queue_node_match->itface->ip;
                    memset(new_arp_hdr ->ar_tha, 0, ETHER_ADDR_LEN);
                    new_arp_hdr ->ar_tip = nexthop_ip_addr;

                    /* Broadcast */
                    printf("[Debug] Broadcast packet.\n");
                    struct sr_ethernet_hdr *new_ethernet_hdr = (struct sr_ethernet_hdr*) new_arp_packet;
                    for (int i=0; i<ETHER_ADDR_LEN;i++) new_ethernet_hdr->ether_dhost[i] = ARP_BROADCAST_IP;
                    memcpy(new_ethernet_hdr->ether_shost, arp_queue_node_match->itface->addr, ETHER_ADDR_LEN);
                    new_ethernet_hdr->ether_type = htons(ETHERTYPE_ARP);
                    arp_queue_node_match->lasttime = time(&raw_time);
                    if(sr_send_packet(sr, new_arp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), arp_queue_node_match->itface->name)){
                        printf("[Debug] Error in broadcasting ARP request packet.\n");
                    };

                    /* Add to packet queue*/
                    printf("[Debug] Add the packet to the queue.\n");
                    struct sr_packet_queue_node *new_packet_queue_node = (struct sr_packet_queue_node*)malloc(sizeof(struct sr_packet_queue_node));
                    new_packet_queue_node->packet = (uint8_t*) malloc(len);
                    new_packet_queue_node->len = len;
                    memcpy(new_packet_queue_node->packet, packet, len);
                    new_packet_queue_node->next = 0;
                    if ((arp_queue_node_match->packet_queue).first) ((arp_queue_node_match->packet_queue).first)->next = new_packet_queue_node;
                    else (arp_queue_node_match->packet_queue).first = new_packet_queue_node;
                    (arp_queue_node_match->packet_queue).last = new_packet_queue_node;
                }
            }else{
                /* If the ARP request for the same IP address was never send before */
                /* Send ARP request */
                printf("[Debug] The ARP request for the same ip address was NEVER sent before.\n");
                struct sr_if* out_if = sr_get_interface(sr, rt_match->interface);
                uint8_t *new_arp_packet = (uint8_t*)malloc(sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr));
                struct sr_arphdr *new_arp_hdr = (struct sr_arphdr*) (new_arp_packet + sizeof(struct sr_ethernet_hdr));
                new_arp_hdr->ar_hln = 6;
                new_arp_hdr->ar_hrd = htons(1);
                new_arp_hdr->ar_op  = htons(ARP_REQUEST);
                new_arp_hdr->ar_pln = 4;
                new_arp_hdr->ar_pro = htons(ETHERTYPE_IP);
                memcpy(new_arp_hdr->ar_sha, out_if->addr, ETHER_ADDR_LEN);
                new_arp_hdr ->ar_sip = out_if->ip;
                memset(new_arp_hdr->ar_tha, 0, ETHER_ADDR_LEN);
                new_arp_hdr ->ar_tip = nexthop_ip_addr;

                /* Broadcast */
                printf("[Debug] Broadcast ARP request packet.\n");
                time_t raw_time;
                struct sr_ethernet_hdr *new_ethernet_hdr = (struct sr_ethernet_hdr*) new_arp_packet;
                for (int i=0; i<ETHER_ADDR_LEN;i++) new_ethernet_hdr->ether_dhost[i] = ARP_BROADCAST_IP;
                memcpy(new_ethernet_hdr->ether_shost, out_if->addr, ETHER_ADDR_LEN);
                new_ethernet_hdr->ether_type = htons(ETHERTYPE_ARP);
                if(sr_send_packet(sr, new_arp_packet, sizeof(struct sr_ethernet_hdr) + sizeof(struct sr_arphdr), out_if->name)){
                    printf("[Debug] Error in broadcasting ARP request packet.\n");
                };

                /* Add to arp queue*/
                printf("[Debug] Add new arp queue record.\n");
                struct sr_arp_queue_node *new_arp_queue_node = (struct sr_arp_queue_node*) malloc(sizeof(struct sr_arp_queue_node));
                new_arp_queue_node->ip_addr = nexthop_ip_addr;
                new_arp_queue_node->itface = out_if;
                new_arp_queue_node->lasttime = time(&raw_time);
                new_arp_queue_node->next = 0;
                (new_arp_queue_node->packet_queue).first = (new_arp_queue_node->packet_queue).last = 0;

                printf("[Debug] Add the packet to the queue.\n");
                struct sr_packet_queue_node *new_packet_queue_node = (struct sr_packet_queue_node*)malloc(sizeof(struct sr_packet_queue_node));
                new_packet_queue_node->packet = (uint8_t*) malloc(len);
                new_packet_queue_node->len = len;
                memcpy(new_packet_queue_node->packet, packet, len);
                new_packet_queue_node->next = 0;
                new_arp_queue_node->lasttime = time(&raw_time);
                (new_arp_queue_node->packet_queue).first = (new_arp_queue_node->packet_queue).last = new_packet_queue_node;

                if(arp_queue.first) arp_queue.last->next = new_arp_queue_node;
                else arp_queue.first = new_arp_queue_node;
                arp_queue.last = new_arp_queue_node;
            }
        }


    }
    else if (packet_type == ETHERTYPE_ARP){
        printf("[Debug] This is an ARP packet.\n");

        struct sr_arphdr *arp_hdr = (struct sr_arphdr*) (packet + sizeof(struct sr_ethernet_hdr));

        printf("[Debug] The source IP address is: ");
        print_ip_address(arp_hdr->ar_sip);
        printf("[Debug] The destination IP address is: ");
        print_ip_address(arp_hdr->ar_tip);

        printf("[Debug] Checking if this ARP is destined to the router.\n");
        struct sr_if *if_match = sr->if_list;
        while (if_match && arp_hdr->ar_tip != if_match->ip) if_match = if_match->next;

        printf("[Debug] Checking if there is a matched arp cache with this target IP address.\n");
        struct sr_arp_cache_node *arp_cache_node_match = arp_cache.first;
        while (arp_cache_node_match && (arp_cache_node_match->ip_addr != arp_hdr->ar_sip)) arp_cache_node_match = arp_cache_node_match->next;

        /* Check if sender's ip address is in the arp cache*/
        /* If it is, it means the router stored this ip's MAC address before, (also means the router requested before)
         * the router can update the corresponding mac address and timeout*/
        if (arp_cache_node_match){
            printf("[Debug] There is a matched arp cache record.\n");
            time_t raw_time;
            memcpy(arp_cache_node_match->mac_addr, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            arp_cache_node_match->timeout = time(&raw_time) + ARP_TIMEOUT;
        }else {
            printf("[Debug] There is NOT a matched arp cache record.\n");
            /* If not, it means the router never stored this ip's MAC address before,
             * it could be:
             * 1. this router doesn't need this information. In this condition, the router doesn't need to do anything.
             * 2. this router asked and got this reply. In this condition, the reply must be destined to the router. */
            /* Create new cache record */
            printf("[Debug] Create a new cache record......");
            struct sr_arp_cache_node *new_arp_cache_node = (struct sr_arp_cache_node *) malloc(
                    sizeof(struct sr_arp_cache_node));
            new_arp_cache_node->ip_addr = arp_hdr->ar_sip;
            memcpy(new_arp_cache_node->mac_addr, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            if (arp_cache.first) arp_cache.last->next = new_arp_cache_node;
            else arp_cache.first = new_arp_cache_node;
            arp_cache.last = new_arp_cache_node;
            new_arp_cache_node->next = NULL;
            time_t raw_time;
            new_arp_cache_node->timeout = time(&raw_time) + ARP_TIMEOUT;
            printf("Finished.\n");
        }
            /* Find the corresponding ARP request and its packets queue */
            /* Send out these packets */
        printf("[Debug] Checking if there is a corresponding ARP queue.\n");
        struct sr_arp_queue_node *arp_queue_node_match = arp_queue.first;
        while(arp_queue_node_match && arp_queue_node_match->ip_addr != arp_hdr->ar_sip){
            arp_queue_node_match = arp_queue_node_match->next;
        }
        if (arp_queue_node_match){
            printf("[Debug] This is a corresponding ARP queue.\n");
            struct sr_packet_queue_node* cur_packet = arp_queue_node_match->packet_queue.first;
            printf("[Debug] Sending out packets in the queue.\n");
            while(cur_packet){
                memcpy(((struct sr_ethernet_hdr*)(cur_packet->packet))->ether_shost, arp_queue_node_match->itface->addr, ETHER_ADDR_LEN);
                memcpy(((struct sr_ethernet_hdr*)(cur_packet->packet))->ether_dhost, arp_hdr->ar_sha, ETHER_ADDR_LEN);
                struct ip* cur_ip_ptr= (struct ip*)((cur_packet->packet) + sizeof(struct sr_ethernet_hdr));
                cur_ip_ptr->ip_sum=0;
                cur_ip_ptr->ip_sum = compute_checksum((uint16_t*) cur_ip_ptr,cur_ip_ptr->ip_hl * 4);
                sr_send_packet(sr, cur_packet->packet, cur_packet->len, arp_queue_node_match->itface->name);
                cur_packet = cur_packet->next;
            }
            printf("[Debug] Remove this ARP queue.\n");
            if (arp_queue.first->ip_addr == arp_hdr->ar_sip){
                arp_queue.first = arp_queue.last = 0;
            }else{
                struct sr_arp_queue_node *arp_queue_node_prev = arp_queue.first;
                while(arp_queue_node_prev){
                    if (arp_queue_node_prev->next->ip_addr == arp_hdr->ar_sip){
                        arp_queue_node_prev->next = arp_queue_node_match->next;
                        if (!arp_queue_node_match->next){
                            arp_queue.last = arp_queue_node_prev;
                        }
                        break;
                    }
                    arp_queue_node_prev = arp_queue_node_prev->next;
                }
            }
        }

        /* An ARP request carries an IP address in the header and asks for the corresponding Ethernet address.
         * Your router needs to check whether the IP address is one of the router’s */
        /* If it is, the router should send an ARP reply containing the Ethernet address. */
        if (if_match && htons(arp_hdr->ar_op) == ARP_REQUEST){
            printf("[Debug] This is an ARP request and destined to the router.\n");
            printf("[Debug] Constructing ARP reply.\n");
            memcpy(ethernet_hdr->ether_dhost, ethernet_hdr->ether_shost, ETHER_ADDR_LEN);
            memcpy(ethernet_hdr->ether_shost, if_match->addr, ETHER_ADDR_LEN);
            memcpy(arp_hdr->ar_tha, arp_hdr->ar_sha, ETHER_ADDR_LEN);
            memcpy(arp_hdr->ar_sha, if_match->addr, ETHER_ADDR_LEN);
            arp_hdr->ar_op = htons(ARP_REPLY);
            arp_hdr->ar_hln = 6;
            arp_hdr->ar_pln = 4;
            arp_hdr->ar_tip = arp_hdr->ar_sip;
            arp_hdr->ar_sip = if_match->ip;
            sr_send_packet(sr, packet, len, interface);
        }
    }


}/* end sr_ForwardPacket */


/*--------------------------------------------------------------------- 
 * Method:
 *
 * https://book.systemsapproach.org/direct/error.html#internet-checksum-algorithm
 *---------------------------------------------------------------------*/