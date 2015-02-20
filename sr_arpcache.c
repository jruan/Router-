#include <netinet/in.h>
#include <stdlib.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <string.h>
#include "sr_arpcache.h"
#include "sr_router.h"
#include "sr_if.h"
#include "sr_protocol.h"
#include "sr_utils.h"
#include "sr_rt.h"



/*
 This function checks if the sent_times is over or equal to 5,
 if it is, drops the request and sends an icmp message back to sender
 saying can not reach. Else, send the request again and update feilds.
 */

 void handle_arpreq(struct sr_arpcache *cache,
                    struct sr_arpreq *req,
                    struct sr_instance *sr
                   )
 {

    time_t now;
    time(&now);

    /*check that the time now subtract the time of last sent if it is greater than 1 sec, if so
     *do the followings within the if statement.
     */

    if(difftime(now, req->sent) > 1.0){

        /*if the number of times sent is greater than or equal to 5, drop
         *request and send icmp message back to sender saying host cant be reached
         */

        if(req->times_sent >= 5){
		struct sr_packet *packets = req->packets;
                struct sr_packet *packet_of_req = NULL;
		struct sr_packet *prev_packet_req = NULL;

		while(packets != packet_of_req){
			packet_of_req = packets;
			while(packet_of_req->next && packet_of_req -> next != prev_packet_req){
				packet_of_req = packet_of_req->next;
			}
                        /*create a buf that will be our new icmp packet to send back*/
                        /*this part is the ethernet header pairt*/
			uint8_t *packet = packet_of_req->buf;
			print_hdrs(packet, packet_of_req->len);
			
			sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;
			sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

			int i = 0;
			for(; i < ETHER_ADDR_LEN; i++){
				ether_hdr->ether_shost[i] = req->sender_mac[i];
			}
			
			uint32_t src_ip = ip_hdr->ip_src;
			struct sr_rt *rt = sr->routing_table;
			char *interface = NULL;

			while(rt){
		                struct in_addr dest_struct = rt->dest;
		                /*when we find a match, return that interface*/
                		if(dest_struct.s_addr  == src_ip){
		                        interface = rt->interface;
					break;
                		}

		                rt = rt->next;
        		}

			struct sr_if *inface = sr_get_interface(sr, interface);

			uint8_t *ip_tmp = malloc(sizeof(sr_ip_hdr_t) + 8);
			
			memcpy(ip_tmp, ip_hdr, sizeof(sr_ip_hdr_t));
			memcpy(ip_tmp + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 8);

			ip_hdr->ip_src = src_ip;
			ip_hdr->ip_dst = inface->ip;
                        memcpy(packet+sizeof(sr_ethernet_hdr_t), ip_hdr, sizeof(sr_ip_hdr_t));

			unsigned int icmp_error_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
			uint8_t *icmp_no_host_packet = construct_icmp_error_packets(packet, 3, 1, icmp_error_len, ip_tmp);

			print_hdrs(icmp_no_host_packet, icmp_error_len);
			sr_send_packet(sr, icmp_no_host_packet, icmp_error_len, interface);
			prev_packet_req = packet_of_req;
                }
                /*destroy this request*/
                sr_arpreq_destroy(cache, req);
        }

        else{
                /*else, resend the request and increment
                *times sent and update sent time to now for this request
                */
                req->times_sent += 1;
                req->sent = now;
		
		/*send out an arp request for each packet*/
                struct sr_packet *p = req->packets;
                while(p){
                        uint8_t *arp_buf = malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

                        /*constructing the ethernet header*/
                        sr_ethernet_hdr_t *arp_ether_hdr = (sr_ethernet_hdr_t *)malloc(sizeof(sr_ethernet_hdr_t));
                        int i = 0;

                        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(p->buf + sizeof(sr_ethernet_hdr_t));
                        uint32_t dest_ip = ip_hdr->ip_dst;

                        char *iface_name = perform_LMP(dest_ip, sr);
                        struct sr_if *outgoing_iface = sr_get_interface(sr, iface_name);

                        /*the src ethernet mac addr will be changed to mac addr of interface router is sending the
                         *arp request to, ehtermnet mac src addr will be the broadcast*/
                        for(; i < ETHER_ADDR_LEN; i++){
                                arp_ether_hdr->ether_shost[i] = outgoing_iface->addr[i];
                                arp_ether_hdr->ether_dhost[i] = 0xFF;
                        }

                        arp_ether_hdr->ether_type = ntohs(ethertype_arp);

                        /*now construct the arp hdr*/
                        sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)malloc(sizeof(sr_arp_hdr_t));
                        unsigned short hrd = ntohs(1);
                        unsigned short pro = ntohs(2048);
                        unsigned char hln = (unsigned char)6;
                        unsigned char pln = (unsigned char)4;
                        unsigned short op = ntohs(arp_op_request);

                        arp_hdr->ar_hrd = hrd;
                        arp_hdr->ar_pro = pro;
                        arp_hdr->ar_hln = hln;
                        arp_hdr->ar_pln = pln;
                        arp_hdr->ar_op = op;
                        arp_hdr->ar_sip = outgoing_iface->ip;
			arp_hdr->ar_tip = req->ip;

                        i = 0;
                        for(; i < ETHER_ADDR_LEN; i++){
                                arp_hdr->ar_sha[i] = arp_ether_hdr->ether_shost[i];
                                arp_hdr->ar_tha[i] = 0x00;
                        }

                        memcpy(arp_buf, arp_ether_hdr, sizeof(sr_ethernet_hdr_t));
                        memcpy(arp_buf + sizeof(sr_ethernet_hdr_t), arp_hdr, sizeof(sr_arp_hdr_t));

                        free(arp_ether_hdr);
                        free(arp_hdr);

                        unsigned int len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);
                        /*print_hdrs(arp_buf, len);*/
                        sr_send_packet(sr, arp_buf, len, iface_name);
                        p = p->next;
                }
        }
    }
 }

/* 
  This function gets called every second. For each request sent out, we keep
  checking whether we should resend an request or destroy the arp request.
  See the comments in the header file for an idea of what it should look like.
*/
void sr_arpcache_sweepreqs(struct sr_instance *sr) { 
    /* Fill this in */
    struct sr_arpcache *arpcache = &(sr -> cache);
    struct sr_arpreq *req;
    for(req = arpcache -> requests; req != NULL; req = req -> next){

        /*traverse thru the list of request for the cache and see if we need to resend and stuff*/
        handle_arpreq(arpcache, req, sr);
    }
}

/* You should not need to touch the rest of this code. */

/* Checks if an IP->MAC mapping is in the cache. IP is in network byte order.
   You must free the returned structure if it is not NULL. */
struct sr_arpentry *sr_arpcache_lookup(struct sr_arpcache *cache, uint32_t ip) {
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpentry *entry = NULL, *copy = NULL;
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if ((cache->entries[i].valid) && (cache->entries[i].ip == ip)) {
            entry = &(cache->entries[i]);
        }
    }
    
    /* Must return a copy b/c another thread could jump in and modify
       table after we return. */
    if (entry) {
        copy = (struct sr_arpentry *) malloc(sizeof(struct sr_arpentry));
        memcpy(copy, entry, sizeof(struct sr_arpentry));
    }
        
    pthread_mutex_unlock(&(cache->lock));
    
    return copy;
}

/* Adds an ARP request to the ARP request queue. If the request is already on
   the queue, adds the packet to the linked list of packets for this sr_arpreq
   that corresponds to this ARP request. You should free the passed *packet.
   
   A pointer to the ARP request is returned; it should not be freed. The caller
   can remove the ARP request from the queue by calling sr_arpreq_destroy. */
struct sr_arpreq *sr_arpcache_queuereq(struct sr_arpcache *cache,
                                       uint32_t ip,
                                       uint8_t *packet,           /* borrowed */
                                       unsigned int packet_len,
                                       char *iface,
				       unsigned char *sender_mac_addr)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req;
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {
            break;
        }
    }
    
    /* If the IP wasn't found, add it */
    if (!req) {
        req = (struct sr_arpreq *) calloc(1, sizeof(struct sr_arpreq));
        req->ip = ip;
	memcpy(req->sender_mac, sender_mac_addr, 6);
        req->next = cache->requests;
        cache->requests = req;
    }
    
    /* Add the packet to the list of packets for this request */
    if (packet && packet_len && iface) {
        struct sr_packet *new_pkt = (struct sr_packet *)malloc(sizeof(struct sr_packet));
        
        new_pkt->buf = (uint8_t *)malloc(packet_len);
        memcpy(new_pkt->buf, packet, packet_len);
        new_pkt->len = packet_len;
		new_pkt->iface = (char *)malloc(sr_IFACE_NAMELEN);
        strncpy(new_pkt->iface, iface, sr_IFACE_NAMELEN);
        new_pkt->next = req->packets;
        req->packets = new_pkt;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* This method performs two functions:
   1) Looks up this IP in the request queue. If it is found, returns a pointer
      to the sr_arpreq with this IP. Otherwise, returns NULL.
   2) Inserts this IP to MAC mapping in the cache, and marks it valid. */
struct sr_arpreq *sr_arpcache_insert(struct sr_arpcache *cache,
                                     unsigned char *mac,
                                     uint32_t ip)
{
    pthread_mutex_lock(&(cache->lock));
    
    struct sr_arpreq *req, *prev = NULL, *next = NULL; 
    for (req = cache->requests; req != NULL; req = req->next) {
        if (req->ip == ip) {            
            if (prev) {
                next = req->next;
                prev->next = next;
            } 
            else {
                next = req->next;
                cache->requests = next;
            }
            
            break;
        }
        prev = req;
    }
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        if (!(cache->entries[i].valid))
            break;
    }
    
    if (i != SR_ARPCACHE_SZ) {
        memcpy(cache->entries[i].mac, mac, 6);
        cache->entries[i].ip = ip;
        cache->entries[i].added = time(NULL);
        cache->entries[i].valid = 1;
    }
    
    pthread_mutex_unlock(&(cache->lock));
    
    return req;
}

/* Frees all memory associated with this arp request entry. If this arp request
   entry is on the arp request queue, it is removed from the queue. */
void sr_arpreq_destroy(struct sr_arpcache *cache, struct sr_arpreq *entry) {
    pthread_mutex_lock(&(cache->lock));
    
    if (entry) {
        struct sr_arpreq *req, *prev = NULL, *next = NULL; 
        for (req = cache->requests; req != NULL; req = req->next) {
            if (req == entry) {                
                if (prev) {
                    next = req->next;
                    prev->next = next;
                } 
                else {
                    next = req->next;
                    cache->requests = next;
                }
                
                break;
            }
            prev = req;
        }
        
        struct sr_packet *pkt, *nxt;
        
        for (pkt = entry->packets; pkt; pkt = nxt) {
            nxt = pkt->next;
            if (pkt->buf)
                free(pkt->buf);
            if (pkt->iface)
                free(pkt->iface);
            free(pkt);
        }
        
        free(entry);
    }
    
    pthread_mutex_unlock(&(cache->lock));
}

/* Prints out the ARP table. */
void sr_arpcache_dump(struct sr_arpcache *cache) {
    fprintf(stderr, "\nMAC            IP         ADDED                      VALID\n");
    fprintf(stderr, "-----------------------------------------------------------\n");
    
    int i;
    for (i = 0; i < SR_ARPCACHE_SZ; i++) {
        struct sr_arpentry *cur = &(cache->entries[i]);
        unsigned char *mac = cur->mac;
        fprintf(stderr, "%.1x%.1x%.1x%.1x%.1x%.1x   %.8x   %.24s   %d\n", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5], ntohl(cur->ip), ctime(&(cur->added)), cur->valid);
    }
    
    fprintf(stderr, "\n");
}

/* Initialize table + table lock. Returns 0 on success. */
int sr_arpcache_init(struct sr_arpcache *cache) {  
    /* Seed RNG to kick out a random entry if all entries full. */
    srand(time(NULL));
    
    /* Invalidate all entries */
    memset(cache->entries, 0, sizeof(cache->entries));
    cache->requests = NULL;
    
    /* Acquire mutex lock */
    pthread_mutexattr_init(&(cache->attr));
    pthread_mutexattr_settype(&(cache->attr), PTHREAD_MUTEX_RECURSIVE);
    int success = pthread_mutex_init(&(cache->lock), &(cache->attr));
    
    return success;
}

/* Destroys table + table lock. Returns 0 on success. */
int sr_arpcache_destroy(struct sr_arpcache *cache) {
    return pthread_mutex_destroy(&(cache->lock)) && pthread_mutexattr_destroy(&(cache->attr));
}

/* Thread which sweeps through the cache and invalidates entries that were added
   more than SR_ARPCACHE_TO seconds ago. */
void *sr_arpcache_timeout(void *sr_ptr) {
    struct sr_instance *sr = sr_ptr;
    struct sr_arpcache *cache = &(sr->cache);
    
    while (1) {
        sleep(1.0);
        
        pthread_mutex_lock(&(cache->lock));
    
        time_t curtime = time(NULL);
        
        int i;    
        for (i = 0; i < SR_ARPCACHE_SZ; i++) {
            if ((cache->entries[i].valid) && (difftime(curtime,cache->entries[i].added) > SR_ARPCACHE_TO)) {
                cache->entries[i].valid = 0;
            }
        }
        
        sr_arpcache_sweepreqs(sr);

        pthread_mutex_unlock(&(cache->lock));
    }
    
    return NULL;
}

