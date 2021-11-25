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

unsigned int forward(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int drop(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int print_local(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int print_forward(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);
unsigned int print_postrouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state);

struct nf_hook_ops hookops_forward = {
      .hooknum = NF_INET_PRE_ROUTING,
      .priority = NF_IP_PRI_FIRST,
      .pf = PF_INET,
      .hook = &forward
};
struct nf_hook_ops hookops_drop = {
      .hooknum = NF_INET_PRE_ROUTING,
      .priority = NF_IP_PRI_FIRST,
      .pf = PF_INET,
      .hook = &drop
};
struct nf_hook_ops hookops_print_local = {
      .hooknum = NF_INET_LOCAL_IN,
      .priority = NF_IP_PRI_FIRST,
      .pf = PF_INET,
      .hook = &print_local
};
struct nf_hook_ops hookops_print_forward = {
      .hooknum = NF_INET_FORWARD,
      .priority = NF_IP_PRI_FIRST,
      .pf = PF_INET,
      .hook = &print_forward
};
struct nf_hook_ops hookops_print_postrouting = {
      .hooknum = NF_INET_POST_ROUTING,
      .priority = NF_IP_PRI_FIRST,
      .pf = PF_INET,
      .hook = &print_postrouting
};

int firewall_init(void) {
   nf_register_net_hook(&init_net, &hookops_forward);
   nf_register_net_hook(&init_net, &hookops_drop);
   nf_register_net_hook(&init_net, &hookops_print_forward);
   nf_register_net_hook(&init_net, &hookops_print_postrouting);
   return 0;
}
 
 
unsigned int forward(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
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
   strcpy(if_forward, "forward: PRE_ROUTING packet ");
   printk("%s(%d;%d;%d;%u.%u.%u.%u;%u.%u.%u.%u)", if_forward, protocol, src_port, dest_port, NIPQUAD(src_ip), NIPQUAD(dest_ip));
   if(src_port == 1111){ // Forwarding packet
      tcp_header->source = 7777;
      tcp_header->dest = 7777;
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
   strcpy(if_forward, "drop: PRE_ROUTING packet ");
   printk("%s(%d;%d;%d;%u.%u.%u.%u;%u.%u.%u.%u)", if_forward, protocol, src_port, dest_port, NIPQUAD(src_ip), NIPQUAD(dest_ip));
   if(src_port == 2222){ // Drop packet
      tcp_header->source = 3333;
      tcp_header->dest = 3333;
      return NF_DROP;
   }
   else{
      return NF_ACCEPT;
   }
   
}

unsigned int print_local(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
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
   if(src_port == 3333){
      strcpy(if_forward, "Dropped packet is catched ");
      printk(KERN_ERR "%s(%d;%d;%d;%u.%u.%u.%u;%u.%u.%u.%u)", if_forward, protocol, src_port, dest_port, NIPQUAD(src_ip), NIPQUAD(dest_ip));
   }

   return NF_ACCEPT;
}


unsigned int print_forward(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
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
      strcpy(if_forward, "forward: FORWARD packet");
      printk("%s(%d;%d;%d;%u.%u.%u.%u;%u.%u.%u.%u)", if_forward, protocol, src_port, dest_port, NIPQUAD(src_ip), NIPQUAD(dest_ip));
   }

   return NF_ACCEPT;
}

unsigned int print_postrouting(void *priv, struct sk_buff *skb, const struct nf_hook_state *state){
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
   return NF_ACCEPT;
}

void firewall_exit(void) {
   nf_unregister_net_hook(&init_net, &hookops_forward);
   nf_unregister_net_hook(&init_net, &hookops_drop);
   nf_unregister_net_hook(&init_net, &hookops_print_local);
   nf_unregister_net_hook(&init_net, &hookops_print_forward);
   nf_unregister_net_hook(&init_net, &hookops_print_postrouting);
}
 
 

MODULE_DESCRIPTION ("netfilter rootkit");
MODULE_LICENSE("GPL");

module_init(firewall_init);
module_exit(firewall_exit);
