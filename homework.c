#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/mm.h>
#include <linux/highmem.h>
#include <linux/skbuff.h>
#include <linux/in.h>
#include <linux/icmp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#define NIPQUAD(addr) \
    ((unsigned char *)&addr)[0], \
    ((unsigned char *)&addr)[1], \
    ((unsigned char *)&addr)[2], \
    ((unsigned char *)&addr)[3]

unsigned int sniff(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int drop(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
struct nf_hook_ops net_hook_sniff;
struct nf_hook_ops net_hook_drop;
 
int firewall_init(void) {
   net_hook_sniff.hooknum =  NF_INET_PRE_ROUTING;
   net_hook_sniff.priority = NF_IP_PRI_FIRST;
   net_hook_sniff.pf = PF_INET;
   net_hook_sniff.hook = &sniff;
   nf_register_net_hook(&init_net, &net_hook_sniff);
   net_hook_drop.hooknum =  NF_INET_LOCAL_IN;
   net_hook_drop.priority = NF_IP_PRI_FIRST;
   net_hook_drop.pf = PF_INET;
   net_hook_drop.hook = &drop;
   nf_register_net_hook(&init_net, &net_hook_drop);
   return 1;
}
 
 
unsigned int sniff(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
   struct tcphdr *tcp_header;
   struct iphdr *ip_header = (struct iphdr*)skb_network_header(skb);
   u_int8_t protocol = ip_header->protocol;
   char if_forward[50] = {0,};
   unsigned int src_port = 0;
   unsigned int dest_port = 0;
   unsigned int src_ip = (unsigned int)ip_header->saddr;
   unsigned int dest_ip = (unsigned int)ip_header->daddr;
   tcp_header = (struct tcphdr *)skb_transport_header(skb);
   src_port = (unsigned int)ntohs(tcp_header->source);
   dest_port = (unsigned int)ntohs(tcp_header->dest);
   if(src_port == 1111)
      strcpy(if_forward, "forward: FORWARD packet ");
   if(src_port == 2222)
      strcpy(if_forward, "drop: FORWARD packet ");
   printk("%s(%d;%d;%d;%u.%u.%u.%u;%u.%u.%u.%u)", if_forward, protocol, src_port, dest_port, NIPQUAD(src_ip), NIPQUAD(dest_ip));
   if(src_port == 1111){ // Forwarding packet
      tcp_header->source = 7777;
      tcp_header->dest = 7777;
   }
   if(src_port == 2222){ // drop packet
      tcp_header->source = 3333;
      tcp_header->dest = 3333;
   }
   return NF_ACCEPT;
}

unsigned int drop(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
   struct tcphdr *tcp_header;
   struct iphdr *ip_header = (struct iphdr*)skb_network_header(skb);
   u_int8_t protocol = ip_header->protocol;
   char if_forward[50] = {0,};
   unsigned int src_port = 0;
   unsigned int dest_port = 0;
   unsigned int src_ip = (unsigned int)ip_header->saddr;
   unsigned int dest_ip = (unsigned int)ip_header->daddr;
   tcp_header = (struct tcphdr *)skb_transport_header(skb);
   src_port = (unsigned int)ntohs(tcp_header->source);
   dest_port = (unsigned int)ntohs(tcp_header->dest);
   if(src_port == 7777){
      strcpy(if_forward, "forward: POST_ROUTING packet ");
      printk("%s(%d;%d;%d;%u.%u.%u.%u;%u.%u.%u.%u)", if_forward, protocol, src_port, dest_port, NIPQUAD(src_ip), NIPQUAD(dest_ip));
   }
   if(src_port == 3333){ // undesirable
      strcpy(if_forward, "drop: POST_ROUTING packet ");
      printk("%s(%d;%d;%d;%u.%u.%u.%u;%u.%u.%u.%u)", if_forward, protocol, src_port, dest_port, NIPQUAD(src_ip), NIPQUAD(dest_ip));
   }
   return NF_ACCEPT;
}

void firewall_exit(void) {
   nf_unregister_net_hook(&init_net, &net_hook_sniff);
   nf_unregister_net_hook(&init_net, &net_hook_drop);
}
 
 

MODULE_DESCRIPTION ("netfilter rootkit");
MODULE_LICENSE("GPL");

module_init(firewall_init);
module_exit(firewall_exit);
