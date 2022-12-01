/*-----------------------------------------------------------------------------
 * File: sr_router.h
 * Date: ?
 * Authors: Guido Apenzeller, Martin Casado, Virkam V.
 * Contact: casado@stanford.edu
 * 90904102 
 *---------------------------------------------------------------------------*/

#ifndef SR_ROUTER_H
#define SR_ROUTER_H

#include <netinet/in.h>
#include <sys/time.h>
#include <stdio.h>

#include "sr_protocol.h"
#ifdef VNL
#include "vnlconn.h"
#endif

/* we dont like this debug , but what to do for varargs ? */
#ifdef _DEBUG_
#define Debug(x, args...) printf(x, ## args)
#define DebugMAC(x) \
  do { int ivyl; for(ivyl=0; ivyl<5; ivyl++) printf("%02x:", \
  (unsigned char)(x[ivyl])); printf("%02x",(unsigned char)(x[5])); } while (0)
#else
#define Debug(x, args...) do{}while(0)
#define DebugMAC(x) do{}while(0)
#endif

#define INIT_TTL 255
#define PACKET_DUMP_SIZE 1024

#define ICMP_ECHOREPLY                0        /* Echo Reply                        */
#define ICMP_DEST_UNREACH        3        /* Destination Unreachable        */
#define ICMP_SOURCE_QUENCH        4        /* Source Quench                */
#define ICMP_REDIRECT                5        /* Redirect (change route)        */
#define ICMP_ECHO                8        /* Echo Request                        */
#define ICMP_TIME_EXCEEDED        11        /* Time Exceeded                */
#define ICMP_PARAMETERPROB        12        /* Parameter Problem                */
#define ICMP_TIMESTAMP                13        /* Timestamp Request                */
#define ICMP_TIMESTAMPREPLY        14        /* Timestamp Reply                */
#define ICMP_INFO_REQUEST        15        /* Information Request                */
#define ICMP_INFO_REPLY                16        /* Information Reply                */
#define ICMP_ADDRESS                17        /* Address Mask Request                */
#define ICMP_ADDRESSREPLY        18        /* Address Mask Reply                */
#define NR_ICMP_TYPES                18

#ifndef ARP_TIMEOUT
#define ARP_TIMEOUT 10
#endif

#ifndef ARP_BROADCAST_IP
#define ARP_BROADCAST_IP 0xff
#endif

/* forward declare */
struct sr_if;
struct sr_rt;

/* ----------------------------------------------------------------------------
 * struct sr_instance
 *
 * Encapsulation of the state for a single virtual router.
 *
 * -------------------------------------------------------------------------- */

struct sr_instance
{
    int  sockfd;   /* socket to server */
#ifdef VNL
    struct VnlConn* vc;
#endif
    char user[32]; /* user name */
    char host[32]; /* host name */
    char template[30]; /* template name if any */
    char auth_key_fn[64]; /* auth key filename */
    unsigned short topo_id;
    struct sockaddr_in sr_addr; /* address to server */
    struct sr_if* if_list; /* list of interfaces */
    struct sr_rt* routing_table; /* routing table */
    FILE* logfile;
    volatile uint8_t  hw_init; /* bool : hardware has been initialized */

    /* -- pwospf subsystem -- */
    struct pwospf_subsys* ospf_subsys;
};

/* -- sr_main.c -- */
int sr_verify_routing_table(struct sr_instance* sr);

/* -- sr_vns_comm.c -- */
int sr_send_packet(struct sr_instance* , uint8_t* , unsigned int , const char*);
int sr_connect_to_server(struct sr_instance* ,unsigned short , char* );
int sr_read_from_server(struct sr_instance* );

/* -- sr_router.c -- */
void sr_init(struct sr_instance* );
void sr_handlepacket(struct sr_instance* , uint8_t * , unsigned int , char* );
static uint16_t compute_checksum(uint16_t *addr, unsigned int count);
static void construct_icmp_reply(uint8_t * packet);
static struct sr_arp_cache_node* ether_addr_in_arp_cache(uint32_t ip_addr);
static struct sr_arp_queue_node* ip_addr_in_arp_queue(uint32_t ip_addr);
static void print_ip_address(uint32_t ip_address);

/* -- sr_if.c -- */
void sr_add_interface(struct sr_instance* , const char* );
void sr_set_ether_ip(struct sr_instance* , uint32_t );
void sr_set_ether_addr(struct sr_instance* , const unsigned char* );
void sr_print_if_list(struct sr_instance* );

#endif /* SR_ROUTER_H */
