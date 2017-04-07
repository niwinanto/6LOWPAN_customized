#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/ip.h>
//
static struct nf_hook_ops nfho;   //net filter hook option struct
struct sk_buff *sock_buff;
struct udphdr *udp_header;          //udp header struct (not used)
struct iphdr *ip_header;            //ip header struct
//
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    sock_buff = skb;

    ip_header = (struct iphdr *)skb_network_header(sock_buff);    //grab network header using accessor

    if(!sock_buff) { return NF_ACCEPT; }

    if (ip_header->protocol==17) {
        udp_header = (struct udphdr *)skb_transport_header(sock_buff);  //grab transport header

        printk(KERN_INFO "got  packet \n");     //log we’ve got udp packet to /var/log/messages
        return NF_DROP;

    }

    return NF_ACCEPT;
}

int init_module()
{
    nfho.hook = hook_func;
    nfho.hooknum = NF_INET_POST_ROUTING;
    //nfho.hooknum = 0;
    nfho.pf = PF_INET;
    nfho.priority = NF_IP_PRI_FIRST;

    nf_register_hook(&nfho);

    return 0;

}

void cleanup_module()
{
    nf_unregister_hook(&nfho);

}

