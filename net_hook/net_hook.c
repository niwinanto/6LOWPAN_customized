#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/ip.h>
//#include <termios.h>
//#include <sys/ioctl.h>
//#include <fcntl.h>
//#include <unistd.h>
//#include <string.h>


int fd;
static struct nf_hook_ops nfho;   //net filter hook option struct
struct sk_buff *sock_buff;
struct udphdr *udp_header;          //udp header struct (not used)
//struct iphdr *ip_header;            //ip header struct
//
unsigned int hook_func(unsigned int hooknum, struct sk_buff *skb, const struct net_device *in, const struct net_device *out, int (*okfn)(struct sk_buff *))
{
    /*sock_buff = skb;

    ip_header = (struct iphdr *)skb_network_header(sock_buff);    //grab network header using accessor

    if(!sock_buff) { return NF_ACCEPT; }

    if (ip_header->protocol==6) {
        udp_header = (struct udphdr *)skb_transport_header(sock_buff);  //grab transport header

        printk(KERN_INFO "got tcp packet \n");     //log we’ve got udp packet to /var/log/messages
        return NF_DROP;

    }

    return NF_ACCEPT;*/



    if (skb)
    {
        struct iphdr *iph = ip_hdr(skb);

        if (iph && iph->protocol && (iph->protocol == IPPROTO_TCP))
        {
            int index;
            char cValue[101];
            char *data;

            struct tcphdr *tcph = tcp_hdr(skb);

            data = (char *) ((unsigned char*) tcph + (tcph->doff * 4));

            printk(KERN_INFO "\n\ntcp hader address = %u", tcph);
            printk(KERN_INFO "TCP source : %hu, TCP  dest : %hu\n", ntohs(tcph->source), ntohs(tcph->dest));
            printk(KERN_INFO "TCP seq : %u, TCP ack_seq : %u\n", ntohl(tcph->seq), ntohl(tcph->ack_seq));
            printk(KERN_INFO "TCP doff : %d, TCP window : %hu\n", tcph->doff * 4, ntohs(tcph->window));
            printk(KERN_INFO "TCP check : 0x%hx, TCP urg_ptr : %hu\n", ntohs(tcph->check), ntohs(tcph->urg_ptr));
            printk(KERN_INFO "FLAGS=%c%c%c%c%c%c\n",
                    tcph->urg ? 'U' : '-',
                    tcph->ack ? 'A' : '-',
                    tcph->psh ? 'P' : '-',
                    tcph->rst ? 'R' : '-',
                    tcph->syn ? 'S' : '-',
                    tcph->fin ? 'F' : '-');
            printk(KERN_INFO "sending packet to : %pI4\n", &iph->daddr);
            printk(KERN_INFO "data len : %d\n", (int) strlen(data));
            printk(KERN_INFO "DATA : %s\n", data);
            printk(KERN_INFO "tcp headerlen = %d\n", tcp_hdrlen(skb));
            unsigned char *tail = skb_tail_pointer(skb);
            unsigned char *end = skb_end_pointer(skb);
            printk(KERN_INFO "skb->head  = %u\n", skb->head);
            printk(KERN_INFO "skb->data  = %u\n", skb->data);
            printk(KERN_INFO "tail pointer  = %u\n", tail);
            printk(KERN_INFO "end pointer  = %u\n", end);
            printk(KERN_INFO "packet len  = %d\n", (int)skb->len);
            printk(KERN_INFO "skb data len  = %d\n", (int)skb->data_len);
            printk(KERN_INFO "header len  = %d\n", (int)skb->hdr_len);

            return NF_ACCEPT;

        }

    }
    return NF_ACCEPT;




    return NF_DROP;
}

int init_module()
{
    /*fd = open("/dev/ttyUSB0",O_RDWR | O_NOCTTY | O_NDELAY);
    if(fd == -1)
        printk(KERN_INFO "usb fd open error %s", strerror(errno));
    */nfho.hook = hook_func;
    //nfho.hooknum = NF_INET_FORWARD;
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

