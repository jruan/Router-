/**********************************************************************
 * file:  sr_router.c
 * date:  Mon Feb 18 12:50:42 PST 2002
 * Contact: casado@stanford.edu
 *
 * Description:
 *
 * This file contains all the functions that interact directly
 * with the routing table, as well as the main entry method
 * for routing.
 *
 **********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <stdlib.h>
#include <string.h>


#include "sr_if.h"
#include "sr_rt.h"
#include "sr_router.h"
#include "sr_protocol.h"
#include "sr_arpcache.h"
#include "sr_utils.h"

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

    /* Initialize cache and cache cleanup thread */
    sr_arpcache_init(&(sr->cache));

    pthread_attr_init(&(sr->attr));
    pthread_attr_setdetachstate(&(sr->attr), PTHREAD_CREATE_JOINABLE);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_attr_setscope(&(sr->attr), PTHREAD_SCOPE_SYSTEM);
    pthread_t thread;

    pthread_create(&thread, &(sr->attr), sr_arpcache_timeout, sr);
    
    /* Add initialization code here! */

} /* -- sr_init -- */

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
  print_hdrs(packet, len);
  /* fill in code here */
  uint16_t ethtype = ethertype(packet);

  /* if the packet is an arp packet, we will see if it is a request or reply first */
  if(ethtype == ethertype_arp){
        /*get the op code to see if request of reply*/
        sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;

        sr_arp_hdr_t *arp_hdr = (sr_arp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        int op_code = ntohs(arp_hdr->ar_op);

        uint32_t targeted_ip = arp_hdr->ar_tip;

        /*request */
        if(op_code == 1){
                /*if it is a request, we must construct and send out a reply*/

                struct sr_if *target_if_walker = sr_check_if_exist(sr, targeted_ip);

                /*checks if the ip requested is one of the routers interface*/
                if(target_if_walker != NULL){
                        struct sr_if *if_walker = sr_get_interface(sr, interface);
                        /*if it is, construct a arp reply and send it back to the requester*/
                        uint8_t *arp_reply = construct_arpreply_packets(ether_hdr, arp_hdr, target_if_walker, if_walker);
                        int len_of_arp = sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t);

                        sr_send_packet(sr, arp_reply, len_of_arp, interface);
                }
        }

        else{
                /*reply*/
                if(op_code == 2){
                        /*if it is a reply, take the sip and tha and cache it*/
                        uint32_t sip = arp_hdr->ar_sip;

                        struct sr_arpcache *cache = (&sr->cache);
                        unsigned char *mac_dest_addr = arp_hdr->ar_sha;

                        struct sr_arpreq *req = sr_arpcache_insert(cache, mac_dest_addr, sip);
                        struct sr_packet *packet_of_this_req = req->packets;

                        /*send out all outstanding packets to the proper destination*/
                        while(packet_of_this_req){
                                /*perform sanity check here*/
				sr_ip_hdr_t * packet_ip_hdr = (sr_ip_hdr_t *)(packet_of_this_req->buf + sizeof(sr_ethernet_hdr_t));
				unsigned int len_of_packet = packet_of_this_req->len;
                                if(perform_cksum_check(packet_of_this_req->buf) != 0 && check_ip_hdr_correctness(packet_ip_hdr, len_of_packet) != 0){

					/*construct a ip buffer to be sent*/
                                        uint8_t *buff = construct_ip_forward_packets(packet_of_this_req->buf, packet_of_this_req->len, arp_hdr->ar_sha);
                                        uint32_t packet_dest_ip = packet_ip_hdr->ip_dst;
                                        char *outgoing_interface = perform_LMP(packet_dest_ip, sr);

                                        /*send it to the proper destination*/
	                                sr_send_packet(sr, buff, len_of_packet, outgoing_interface);
                                        packet_of_this_req = packet_of_this_req->next;
                                }
                        }
                        /*destroy the request now*/
                        sr_arpreq_destroy((&sr->cache), req);
                }
        }
  }

  /*if it is an ip packet, must check sanity of every packet, figure if is for me or not, if it is
   *see if icmp request for ping and then ping a response back, else if it is a tcp/udp protocol
   *send back icmp error response, if not for me and for me, perform lmp and forward it to correct one*/
  if(ethtype == ethertype_ip){
        sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        uint32_t dest_ip = ip_hdr->ip_dst;
        uint16_t ttl = ip_hdr->ip_ttl;

        /*first perform sanity check to see if any corruptions*/
        /*if detects corruption, drop/ignore the packet*/
	 if(perform_cksum_check(packet) != 0 && check_ip_hdr_correctness(ip_hdr, len) != 0){

                /*if sanity passes, construct an icmp response and send it back*/
                /*if the dest ip of the ip header is one of our router's interface, then then ip packet is for router*/
                if(sr_check_if_exist(sr, dest_ip) != NULL){

                        /*if the ttl after subtracting one is less than zero, we must discard the packet
                         *and send an icmp response back. Expired!*/
                        if(ttl - 1 < 0){
                                struct sr_if *inface = sr_get_interface(sr, interface);
                                uint8_t *ip_tmp = malloc(sizeof(sr_ip_hdr_t) + 8);

                                memcpy(ip_tmp, ip_hdr, sizeof(sr_ip_hdr_t));
                                memcpy(ip_tmp + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 8);

                                ip_hdr->ip_dst = inface->ip;
                                memcpy(packet+sizeof(sr_ethernet_hdr_t), ip_hdr, sizeof(sr_ip_hdr_t));

                                unsigned int ttl_error_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                                uint8_t *icmp_ttl_response = construct_icmp_error_packets(packet, 11, 0, ttl_error_len, ip_tmp);

                                sr_send_packet(sr, icmp_ttl_response, ttl_error_len, interface);
                        }

                        /*if ttl is 0 or more, not expire and ip hdr correct so we can proceed to checking if it is a ping request
                         *or wrong protocol*/
                        else{
                                /*If it is icmp ping request*/
                                if(ip_hdr->ip_p == ip_protocol_icmp){
                                        /*then construct a ping response back to the requester*/
                                        uint8_t *icmp_response = construct_icmp_response_packets(packet, 0, 0, len);
	                                sr_send_packet(sr, icmp_response, len, interface);
                                }

                                /*if it is tcp/udp protocol, send back icmp error*/
                                else{
                                        uint8_t *ip_tmp = malloc(sizeof(sr_ip_hdr_t) + 8);

                                        memcpy(ip_tmp, ip_hdr, sizeof(sr_ip_hdr_t));
                                        memcpy(ip_tmp + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 8);
                                        unsigned int icmp_port_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                                        uint8_t *icmp_port_response = construct_icmp_error_packets(packet, 3, 3, icmp_port_len, ip_tmp);
                                        sr_send_packet(sr, icmp_port_response, icmp_port_len, interface);
                                }
                        }
                }

                /*else it is not for us, we must forward it to proper table*/
                else{

                        /*if ttl expired, drop and send icmp back*/
                        if(ttl - 1 <= 0){
                                struct sr_if *inface = sr_get_interface(sr, interface);
                                uint8_t *ip_tmp = malloc(sizeof(sr_ip_hdr_t) + 8);

                                memcpy(ip_tmp, ip_hdr, sizeof(sr_ip_hdr_t));
                                memcpy(ip_tmp + sizeof(sr_ip_hdr_t), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), 8);

                                ip_hdr->ip_dst = inface->ip;
                                memcpy(packet+sizeof(sr_ethernet_hdr_t), ip_hdr, sizeof(sr_ip_hdr_t));

                                unsigned int ttl_error_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                                uint8_t *icmp_ttl_response = construct_icmp_error_packets(packet, 11, 0, ttl_error_len, ip_tmp);

                                sr_send_packet(sr, icmp_ttl_response, ttl_error_len, interface);
                        }

                        /*ttl did not expire and no error with ip hdr so proceed to forwarding it*/
                        else{
                                char* outgoing_if = perform_LMP(dest_ip,sr);
                                /*send the packet with new ethernet out that interface to the correct dest*/
                                if(outgoing_if != NULL){
                                        struct sr_if *outface = sr_get_interface(sr, outgoing_if);
                                        int i = 0;
					unsigned char ether_shost_tmp[ETHER_ADDR_LEN];

                                        /*change the mac src addr of the packet to the one of the outgoing iface*/
                                        for(; i < ETHER_ADDR_LEN; i++){
						ether_shost_tmp[i] = ether_hdr->ether_shost[i];
                                                ether_hdr->ether_shost[i] = outface->addr[i];
                                        }

                                        /*get the mac dest addr of our dest_ip*/
                                        struct sr_arpentry *arpentry = sr_arpcache_lookup((&sr->cache), dest_ip);

                                        /*check cache if there is even the entry, if
                                         *there is, get mac and send the ip packet along*/
                                        if(arpentry != NULL){
                                                uint8_t *mac_addr = arpentry->mac;
                                                uint8_t *outgoing_buffer = construct_ip_forward_packets(packet, len, mac_addr);

                                                /*send out new outgoing_buffer packet*/
	                                        sr_send_packet(sr, outgoing_buffer, len, outgoing_if);
					 }

                                        else{
                                                struct sr_arpreq *arp_request = sr_arpcache_queuereq((&sr->cache), dest_ip, packet, len, interface, ether_shost_tmp);
                                                handle_arpreq((&sr->cache), arp_request, sr);
                                        }
                                }

                                /*else, if no lmp was found, send icmp error response back to the sender*/
                                else{
                                        /*must change the packets ip_dest to interface ip because the orig dest ip could
                                          not be found. Thus, when we send icmp response back, the src ip is from the interface
                                          and not the not found ip*/

                                        struct sr_if *inface = sr_get_interface(sr, interface);

                                        uint8_t *ip_tmp = malloc(sizeof(sr_ip_hdr_t) + 8);
                                        ip_hdr->ip_ttl--;

                                        memcpy(ip_tmp, ip_hdr, sizeof(sr_ip_hdr_t));
                                        memcpy(ip_tmp + sizeof(sr_ip_hdr_t), icmp_hdr, 8);

                                        ip_hdr->ip_dst = inface->ip;

                                        memcpy(packet+sizeof(sr_ethernet_hdr_t), ip_hdr, sizeof(sr_ip_hdr_t));
                                        unsigned int icmp_error_len = sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) + sizeof(sr_icmp_t3_hdr_t);
                                        uint8_t *icmp_no_match_found_response = construct_icmp_error_packets(packet, 3, 0, icmp_error_len, ip_tmp);
                                        /*send this back the requester*/
                                        sr_send_packet(sr, icmp_no_match_found_response,icmp_error_len, interface);
                                }
                        }
                }
	}
  }

}/* end sr_ForwardPacket */


/* 
 Checks if the version number, header length, and length of the packet is correct
 If so, return 1, else return 0.
*/
int check_ip_hdr_correctness(sr_ip_hdr_t *ip_hdr, unsigned int len){
	if(ip_hdr->ip_v != 4){
		return 0;
	}
	
	if(ip_hdr->ip_hl != 5){
		return 0;
	}

	uint16_t iplen = ntohs(ip_hdr->ip_len);
	if(len - sizeof(sr_ethernet_hdr_t) != iplen){
		return 0;
	}	

	return 1;
}/* end of check_ip_hdr_correctness */


/*
 Performs a longest matching prefix search on a given destination ip to the 
 ips of the routing table.
*/
char* perform_LMP(uint32_t dest_ip, struct sr_instance *sr){
        struct sr_rt *rt = sr->routing_table;

        /*go through the routing table*/
        while(rt){
                struct in_addr dest_struct = rt->dest;
                struct in_addr mask_struct = rt->mask;

                uint32_t dest_ip_after_mask = dest_ip & mask_struct.s_addr;

                /*when we find a match, return that interface*/
                if((dest_struct.s_addr & mask_struct.s_addr) == dest_ip_after_mask){
                        return rt->interface;
                }

                rt = rt->next;
        }

        /*no match, return null*/
        return NULL;
}/* end of perform_LMP */

/*
 performs a checksum check on the packet to make sure the checksum is right
*/
int perform_cksum_check(uint8_t *packet){
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        uint16_t ip_chksum = ip_hdr->ip_sum;

        uint8_t *sum_buff = malloc(sizeof(sr_ip_hdr_t) - sizeof(uint16_t));
        memcpy(sum_buff, packet + sizeof(sr_ethernet_hdr_t), sizeof(sr_ip_hdr_t) - sizeof(uint16_t) - (sizeof(uint32_t) * 2));
        memcpy(sum_buff + sizeof(sr_ip_hdr_t) - sizeof(uint16_t) - (sizeof(uint32_t) * 2), packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t) - (sizeof(uint32_t) *2), sizeof(uint32_t) * 2);

        /*checks if the sum is the same*/
        if(ip_chksum == cksum(sum_buff, sizeof(sr_ip_hdr_t) - sizeof(uint16_t)))
                return 1;

        return 0;
}/* end of perform_cksum_check */


/*
 Construct an arp reply packet that replies back with the targeted mac address
 the request was looking for in the src mac addres section now.
*/
uint8_t* construct_arpreply_packets(sr_ethernet_hdr_t* ether_hdr, sr_arp_hdr_t* arp_hdr, struct sr_if *if_walker, struct sr_if *iface){

        uint8_t *arp_reply = (uint8_t *)malloc(sizeof(sr_ethernet_hdr_t) + sizeof(sr_arp_hdr_t));

        /*constructing the ethernet header*/
        /*the original src ether address becomes the recipient now of our arp reply*/
        /*the new src address is the ether src and ip src of the outgoing interface*/

        int i = 0;
        for(; i < ETHER_ADDR_LEN; i++){
               ether_hdr->ether_dhost[i] = ether_hdr->ether_shost[i];
               ether_hdr->ether_shost[i] = iface->addr[i];
        }

        ether_hdr->ether_type = ntohs(ethertype_arp);

        /*puts the the header into our new packet*/
        memcpy(arp_reply, ether_hdr, sizeof(sr_ethernet_hdr_t));

        /*constructing the arp reply header*/
        unsigned short op = ntohs(arp_op_reply);
        arp_hdr->ar_op = op;

        i = 0;
        for(; i < ETHER_ADDR_LEN; i++){
                arp_hdr->ar_tha[i] = arp_hdr->ar_sha[i];
                arp_hdr->ar_sha[i] = if_walker->addr[i];
        }

        arp_hdr->ar_tip = arp_hdr->ar_sip;
        arp_hdr->ar_sip = if_walker->ip;

        /*puts arp header into new packet*/
        memcpy(arp_reply + sizeof(sr_ethernet_hdr_t), arp_hdr, sizeof(sr_arp_hdr_t));
        return arp_reply;
}/* end of construct_arpreply_packets */


/*
 Construct icmp error packets. The error depends on the type and code of the
 error we want to send back
 */
uint8_t* construct_icmp_error_packets(uint8_t *packet,
                                      int type,
                                      int code,
                                      unsigned int len,
                                      uint8_t *ip_hdr_tmp)
{
        sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));

        int i = 0;
        uint8_t ether_dest_tmp;
        uint8_t *icmp_response = malloc(len);

        /*constructs the ethernet header of the icmp response packet*/
        for(; i < ETHER_ADDR_LEN; i++){
                ether_dest_tmp = ether_hdr->ether_dhost[i];
                ether_hdr->ether_dhost[i] = ether_hdr->ether_shost[i];
                ether_hdr->ether_shost[i] = ether_dest_tmp;
        }

        ether_hdr->ether_type = ntohs(ethertype_ip);
        memcpy(icmp_response, ether_hdr, sizeof(sr_ethernet_hdr_t));

        /*constructing the ip header by switching ip dest with src, recalculating chksum....etc*/
        uint32_t ip_dest_tmp = ip_hdr->ip_dst;
        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = ip_dest_tmp;
        ip_hdr->ip_ttl = (uint8_t)INIT_TTL;

        uint16_t iplen = len - sizeof(sr_ethernet_hdr_t);
        ip_hdr->ip_len = ntohs(iplen);
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_sum = ntohs(0x0000);

        uint16_t cksums = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        ip_hdr->ip_sum = cksums;

        memcpy(icmp_response + sizeof(sr_ethernet_hdr_t), ip_hdr, sizeof(sr_ip_hdr_t));
		
	/*construct t3 icmp header*/
        sr_icmp_t3_hdr_t * t3_icmp_hdr = malloc(sizeof(sr_icmp_t3_hdr_t));

        t3_icmp_hdr->icmp_type = (uint8_t)type;
        t3_icmp_hdr->icmp_code = (uint8_t)code;

        t3_icmp_hdr->unused = ntohs(0x0000);
        t3_icmp_hdr->next_mtu = ntohs(0x0000);

        memcpy(t3_icmp_hdr->data, ip_hdr_tmp, ICMP_DATA_SIZE);
        t3_icmp_hdr->icmp_sum = ntohs(0x0000);

        uint16_t icmp_cksum = cksum(t3_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
        t3_icmp_hdr->icmp_sum = icmp_cksum;

        memcpy(icmp_response + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), t3_icmp_hdr, sizeof(sr_icmp_t3_hdr_t));
        free(t3_icmp_hdr);
        free(ip_hdr_tmp);
        return icmp_response;
}/*end of construct_icmp_error_packets */


/*
 Constructs icmp ping response packets. If a request was to one of our routers interface,
 this function is called to create back a response packet
*/
uint8_t* construct_icmp_response_packets(uint8_t *packet,
                                         int type,
                                         int code,
                                         unsigned int len)
{
        sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)packet;
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t));
        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        int i = 0;
        uint8_t ether_dest_tmp;
        uint8_t *icmp_response = malloc(len);

        /*constructs the ethernet header of the icmp response packet*/
        for(; i < ETHER_ADDR_LEN; i++){
                ether_dest_tmp = ether_hdr->ether_dhost[i];
                ether_hdr->ether_dhost[i] = ether_hdr->ether_shost[i];
                ether_hdr->ether_shost[i] = ether_dest_tmp;
        }

        ether_hdr->ether_type = ntohs(ethertype_ip);
        memcpy(packet, ether_hdr, sizeof(sr_ethernet_hdr_t));

        /*constructing the ip header by switching ip dest with src, recalculating chksum....etc*/
        uint32_t ip_dest_tmp = ip_hdr->ip_dst;
        ip_hdr->ip_dst = ip_hdr->ip_src;
        ip_hdr->ip_src = ip_dest_tmp;
	ip_hdr->ip_ttl = (uint8_t)INIT_TTL;
        ip_hdr->ip_p = ip_protocol_icmp;
        ip_hdr->ip_sum = ntohs(0x0000);

        uint16_t cksums = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        ip_hdr->ip_sum = cksums;

        memcpy(packet+sizeof(sr_ethernet_hdr_t), ip_hdr, sizeof(sr_ip_hdr_t));

        /*construct icmp header now*/
        icmp_hdr->icmp_type = (uint8_t)type;
        icmp_hdr->icmp_code = (uint8_t)code;
	icmp_hdr->icmp_sum = ntohs(0x0000);
        uint16_t icmp_cksum = cksum(icmp_hdr, sizeof(sr_icmp_hdr_t));
        icmp_hdr->icmp_sum = icmp_cksum;

        memcpy(packet + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_hdr, sizeof(sr_icmp_hdr_t));

        /*copy the new info from the packet to our icmp response*/
        memcpy(icmp_response, packet, len);
        return icmp_response;
}/* end of construct icmp_response_packets */


/*
 construct a forwarding packet that will take a packet/buf, then decrement the  
 ttl, and forward it to the new dest addr
 */
uint8_t* construct_ip_forward_packets(uint8_t *buf, unsigned int len, uint8_t *mac_dst){
        uint8_t *buff = malloc(len);
        sr_ethernet_hdr_t *ether_hdr = (sr_ethernet_hdr_t *)(buf);

        /*Change the destination mac address to the recently discovered mac address for destination*/
        int i = 0;
        for(; i < ETHER_ADDR_LEN; i++){
                ether_hdr->ether_dhost[i] = mac_dst[i];
        }

        /*decrement the ip ttl by one and compute the new chksum*/
        sr_ip_hdr_t *ip_hdr = (sr_ip_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t));
        ip_hdr->ip_ttl -= 1;
        ip_hdr->ip_sum = ntohs(0x0000);
	
        uint16_t new_chksum = cksum(ip_hdr, sizeof(sr_ip_hdr_t));
        ip_hdr->ip_sum = new_chksum;

        memcpy(buf, ether_hdr, sizeof(sr_ethernet_hdr_t));
        memcpy(buf + sizeof(sr_ethernet_hdr_t), ip_hdr, sizeof(sr_ip_hdr_t));

        sr_icmp_hdr_t *icmp_hdr = (sr_icmp_hdr_t *)(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t));

        memcpy(buf + sizeof(sr_ethernet_hdr_t) + sizeof(sr_ip_hdr_t), icmp_hdr, sizeof(sr_icmp_hdr_t));
        /*copy the new infos into the new packet to be sent*/
        memcpy(buff, buf, len);

        /*return the buff to send now with the dest mac addr now set*/
	return buff;
}/* end of construct_ip_forward_packets */


