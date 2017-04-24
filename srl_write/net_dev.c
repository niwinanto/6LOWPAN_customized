#include <linux/init.h>             // Macros used to mark up functions e.g., __init __exit
#include <linux/module.h>           // Core header for loading LKMs into the kernel
#include <linux/kernel.h>           // Contains types, macros, functions for the kernel
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <asm/uaccess.h>  /* For get_fs() */
#include <linux/module.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/slab.h>

#define NALP 		0
#define UC_IPV6 	0x41
#define LOWPAN_HC1 	0x42
#define LOWPAN_BC0	0x50
#define MESH 		0x80
#define FRAG1 		0xc0
#define FRAGN		0xe0

static struct nf_hook_ops nfho;
static struct net_device *lowpan;
static struct file *rc;
static unsigned char eui_64[8]={[3]=0xff,0xfe};
static unsigned char ipv6_addr[16]={[0]=0xfe,0x80};
//static unsigned char packet[81];
static struct iphdr * ip_header;
static struct udphdr * udp_header;
static struct tcphdr * tcp_header ;

static struct HC1_encoded{
	unsigned char s_pi:2;
	unsigned char d_pi:2;
	unsigned char tc_fl:1;
	unsigned char nh:2;
	unsigned char hc2:1;
}HC1encoded;

static struct HC2_encoded{
	unsigned char s_port:1;
	unsigned char d_port:1;
	unsigned char len:1;
}HC2encoded;

static void lowpan_set_addr(void){
	char buffer[50];
	int j;
	struct net_device *eth = dev_get_by_name(&init_net,"eth0");
	if(eth){
		memcpy(eui_64,eth->perm_addr,3);
		memcpy(eui_64+5,eth->perm_addr+3,3);
		memcpy(lowpan->perm_addr,eui_64,8);
		memcpy(lowpan->dev_addr,eui_64,8);
		lowpan->addr_len=8;
		j=0;
		for(int i=0;i<8;i+=1)
		{
			sprintf(buffer+j,"%02x:",lowpan->dev_addr[i]);
			j+=3;
		}
		printk(KERN_INFO"MAC %s\n",buffer);
		memset(ipv6_addr+2,0,6);
		memcpy(ipv6_addr+8,eui_64,8);
		j=0;
		for(int i=0;i<16;i+=2)
		{
			sprintf(buffer+j,"%02x%02x:",ipv6_addr[i],ipv6_addr[i+1]);
			j+=5;
		}
		printk(KERN_INFO"IPv6 %s\n",buffer);
	}
}

static void ipv6_HC1(int protocol)
{
	HC1encoded.s_pi=3; //source Prefix and Identifier Compressed
	HC1encoded.d_pi=3; //destination Prefix and Identifier Compressed
	HC1encoded.tc_fl=1; //Trafic class and Flow label zero
	switch(protocol){   //Next Header assignment
		case IPPROTO_UDP:
			HC1encoded.nh=1; break;
		case IPPROTO_ICMP:
			HC1encoded.nh=2; break;
		case IPPROTO_TCP:
			HC1encoded.nh=3; break;
		default:
			HC1encoded.nh=0; break;
	}
	if(protocol==IPPROTO_UDP||protocol==IPPROTO_ICMP||protocol==IPPROTO_TCP){
		HC1encoded.hc2=1;
	}
	else HC1encoded.hc2=0;
}

static void udp_hc2(struct udphdr *udp_header){
	if((udp_header->source>=0xf0b0)&&(udp_header->source<=0xf0bf))
		HC2encoded.s_port=1;    //Partially Compressed source Port
	else HC2encoded.s_port=0;
	if((udp_header->dest>=0xf0b0)&&(udp_header->dest<=0xf0bf))
		HC2encoded.d_port=1;    //Partially Compressed dest Port
	else HC2encoded.d_port=0;
	HC2encoded.len=1;           //Compressed Length
}

unsigned int hook_func(void *priv,struct sk_buff *skb,const struct nf_hook_state *state){
	char *raw_data=NULL;
	//unsigned int raw_data_len=0;
	ip_header = (struct iphdr *)skb_network_header(skb);
	if(ip_header)
	if(ip_header->version==4){
		//printk("Its a IPv4 packet\n");
		if(ip_header->protocol==IPPROTO_TCP){
			tcp_header = (struct tcphdr *)skb_transport_header(skb);
			raw_data = (char *)(tcp_header + tcp_header->doff * 4);
			//printk("TCP Data %u\n",(unsigned int)raw_data);
		}
		else if(ip_header->protocol==IPPROTO_UDP||ip_header->protocol==IPPROTO_ICMP){
			udp_header = (struct udphdr *)skb_transport_header(skb);
			raw_data = (char *)(udp_header + 8);
			//printk("UDP Data %u\n",(unsigned int)raw_data);
		}
		ipv6_HC1(ip_header->protocol);
		if(HC1encoded.hc2==1){
			if(HC1encoded.nh==1)
				udp_hc2(udp_header);
			else if(HC1encoded.nh==3){}
			else {}//drop packets;
		}
	}
	/*if(raw_data)
	{
		while(raw_data++<=(char *)skb->tail)
			raw_data_len++;
		if(raw_data_len){
			printk("Data length %u bytes\n",raw_data_len);
			temp = kmalloc(raw_data_len,GFP_KERNEL);
			if(temp){
				strncpy(temp,raw_data,raw_data_len);
				printk("DATA: %s\n",temp);
			}
		}
	}*/
	return NF_ACCEPT;
}

static int lowpan_open(struct net_device *dev){
	printk(KERN_INFO"6lowpan0 is up and running\n");
	netif_start_queue(dev);
	return 0;
}

static int lowpan_close(struct net_device *dev){
	printk(KERN_INFO"6lowpan0 is stopped\n");
	netif_stop_queue(dev);
	return 0;
}

/*static void write_to_usb(char *packet){

	struct file * const fileP = rc;
	printk(KERN_INFO"Writing %s to serial device\n",packet);
	if (!fileP->f_op)
        printk("%s: File has no file operations registered!",__FUNCTION__);
    else {
        ssize_t (*writeOp)(struct file *, const char *, size_t, loff_t *) = fileP->f_op->write;
		if (writeOp == NULL)
            printk("%s: File has no write operation registered!",__FUNCTION__);
        else {
            ssize_t rl;
            mm_segment_t oldfs;
            const char *buffer = packet;
			fileP->f_pos = 0;
            oldfs = get_fs();
            set_fs(get_ds());
<<<<<<< HEAD

            rl = writeOp(fileP, skb->dev->name, sizeof(skb->dev->name), &fileP->f_pos);
            rl = writeOp(fileP, skb->data, sizeof(skb->truesize), &fileP->f_pos);
            printk("head %s : data %s: tusz %d\n",skb->head,skb->data,skb->truesize);
            set_fs(oldfs);

            if (rl < 0) {
                printk("%s: filesystem driver's write() operation for "
=======
			rl = writeOp(fileP, buffer, sizeof(buffer), &fileP->f_pos);
			set_fs(oldfs);
			if (rl < 0) printk("%s: filesystem driver's write() operation for "
>>>>>>> d9525cfd67ff8b5ee836e3c9ff2c403513901912
                        "returned errno %d. ", __FUNCTION__, (int)-rl);
            else if (rl != sizeof(buffer)) printk("%s: write returned only %d bytes instead of %d.\n",__FUNCTION__, (int)rl, (int)sizeof(buffer));
            else printk("%s: write was successful.\n", __FUNCTION__);
        }
    }
}*/
static netdev_tx_t lowpan_xmit(struct sk_buff *skb,struct net_device *dev){
	//char packet[] = "This is the test data\n";
	//write_to_usb(packet);
    return NETDEV_TX_OK;
}


static const struct net_device_ops dev_ops = {
	.ndo_open = lowpan_open,
	.ndo_stop = lowpan_close,
	.ndo_start_xmit = lowpan_xmit
};

static int lowpan_init(struct net_device *dev){
	dev->netdev_ops = &dev_ops;
	printk(KERN_INFO"6lowpan0 Initialized");
	return 0;
}

static int firstmod_init(void){
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_POST_ROUTING;
	nfho.pf = PF_INET;
	nfho.priority = NF_IP_PRI_FIRST;
	nf_register_hook(&nfho);
    rc = filp_open("/dev/ttyUSB0", O_CREAT, 0);
	lowpan = alloc_netdev(10,"6lowpan0",0,(void *)lowpan_init);
	if(!register_netdev(lowpan))
		printk(KERN_INFO"%s is registered\n",lowpan->name);
	lowpan_set_addr();
	return 0;
}

static void firstmod_exit(void){
     nf_unregister_hook(&nfho);
     unregister_netdev(lowpan);
     printk(KERN_INFO"%s is unregistered\n",lowpan->name);
     free_netdev(lowpan);
    filp_close(rc,NULL);
}

module_init(firstmod_init);
module_exit(firstmod_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Niwin Anto");
