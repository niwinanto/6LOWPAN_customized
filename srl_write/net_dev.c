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
#include <asm/byteorder.h>

#define NALP 		0
#define UC_IPV6 	0x41
#define LOWPAN_HC1 	0x42
#define LOWPAN_BC0	0x50
#define MESH 		2
#define FRAG1 		0x18
#define FRAGN		0x1c

static unsigned packet_number=0; 
static struct nf_hook_ops nfho;
static struct net_device *lowpan;
static struct file *rc;
static unsigned char eui_64[8]={[3]=0xff,0xfe},dest_hwaddr[8]={[3]=0xff,0xfe};
static unsigned char ipv6_addr[16]={[0]=0xfe,0x80};
static unsigned char mesh_size,HC1_size=1,udp_size=1,frag_size=4,tcp_size=1;
static unsigned char packet[81],HC1_dispatch[1]={0x42},hoplimit[1];
static char buffer[50];
static struct iphdr * ip_header;
static struct udphdr * udp_header;
static struct tcphdr * tcp_header ;

static struct fragHeader{
	#ifdef __LITTLE_ENDIAN_BITFIELD
		unsigned char garbage:3;
		unsigned char type:5;
	#endif
	#ifdef __BIG_ENDIAN_BITFIELD
		unsigned char type:5;
		unsigned char garbage:3;
	#endif
	unsigned char dgram_size;
	unsigned short dgram_tag; 
}frag_header;

static struct meshHeader{
	#ifdef __LITTLE_ENDIAN_BITFIELD
		unsigned char hops_lft:4;
		unsigned char F:1;
		unsigned char V:1;
		unsigned char type:2;
	#endif
	#ifdef __BIG_ENDIAN_BITFIELD
		unsigned char type:2;
		unsigned char V:1;
		unsigned char F:1;
		unsigned char hops_lft:4;
	#endif
	unsigned char addr[16];
}mesh_header;

static struct HC1_encoded{
	#ifdef __LITTLE_ENDIAN_BITFIELD
		unsigned char hc2:1;
		unsigned char nh:2;
		unsigned char tc_fl:1;
		unsigned char d_pi:2;
		unsigned char s_pi:2;
	#endif
	#ifdef __BIG_ENDIAN_BITFIELD
		unsigned char s_pi:2;
		unsigned char d_pi:2;
		unsigned char tc_fl:1;
		unsigned char nh:2;
		unsigned char hc2:1;
	#endif
}HC1encoded;

static struct udpHeader{
	#ifdef __LITTLE_ENDIAN_BITFIELD
		unsigned char garbage:5;
		unsigned char len:1;
		unsigned char d_port:1;
		unsigned char s_port:1;
	#endif
	#ifdef __BIG_ENDIAN_BITFIELD
		unsigned char s_port:1;
		unsigned char d_port:1;
		unsigned char len:1
		unsigned char garbage:5;
	#endif
}udphdr;

static struct tcpHeader{
	#ifdef __LITTLE_ENDIAN_BITFIELD
		unsigned char len:1;
		unsigned char d_port:1;
		unsigned char s_port:1;
	#endif
	#ifdef __BIG_ENDIAN_BITFIELD
		unsigned char s_port:1;
		unsigned char d_port:1
		unsigned char len:1;
	#endif
}tcphdr;

static void write_to_usb(char *packet,unsigned char size){

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
			rl = writeOp(fileP, buffer, size, &fileP->f_pos);
			set_fs(oldfs);
			if (rl < 0) printk("%s: filesystem driver's write() operation for "
                        "returned errno %d. ", __FUNCTION__, (int)-rl);
            else if (rl != size) printk("%s: write returned only %d bytes instead of %d.\n",__FUNCTION__, (int)rl, size);
            else printk("%s: write was successful.\n", __FUNCTION__);
        }
    }
}

static void lowpan_set_addr(void){
	int j;
	char dst_mac[6]={0x74,0x2b,0x62,0xf1,0x85,0x62};
	struct net_device *eth = dev_get_by_name(&init_net,"eth0");
	if(eth){
		memcpy(eui_64,eth->perm_addr,3);
		memcpy(eui_64+5,eth->perm_addr+3,3);
		memcpy(lowpan->perm_addr,eui_64,8);
		memcpy(lowpan->dev_addr,eui_64,8);
		lowpan->addr_len=8;
		memcpy(dest_hwaddr,dst_mac,3);
		memcpy(dest_hwaddr+5,dst_mac+3,3);
		j=0;
		for(int i=0;i<8;i+=1)
		{
			sprintf(buffer+j,"%02x:",dest_hwaddr[i]);
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

static void gen_mesh_header(int src_mode,int dst_mode){
	mesh_header.type = MESH;
	mesh_header.V = src_mode;
	mesh_header.F = dst_mode;
	mesh_header.hops_lft = 0xe;
	mesh_size = 0;
	if(!src_mode){
		memcpy(mesh_header.addr,eui_64,8);
		mesh_size+=8;
	}
	else{
		memcpy(mesh_header.addr,eui_64,2);
		mesh_size+=2;
	}
	if(!dst_mode){
		memcpy(mesh_header.addr+mesh_size,dest_hwaddr,8);
		mesh_size+=8;
	}
	else{
		memcpy(mesh_header.addr+mesh_size,dest_hwaddr,2);
		mesh_size+=2;
	}
	mesh_size+=1;   //For the Type, V, F, Hops_left
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
		udphdr.s_port=1;    //Partially Compressed source Port
	else udphdr.s_port=0;
	if((udp_header->dest>=0xf0b0)&&(udp_header->dest<=0xf0bf))
		udphdr.d_port=1;    //Partially Compressed dest Port
	else udphdr.d_port=0;
	udphdr.len=1;           //Compressed Length
}

static void gen_packet(struct sk_buff *skb,unsigned char *data){
	unsigned char tot_size;
	unsigned short grand=0;
	//char newline[3]="End";
	unsigned short bit16 = (unsigned char *)skb->tail - data;
	unsigned char size=0,offset=0,dgram_offset[1]={offset},free_space,req1,req2;
	unsigned char port[1];
	unsigned short s_port_16,d_port_16,checksum_16;
	memcpy(packet,&mesh_header,mesh_size); size += mesh_size; req1 = size;
	frag_header.type = FRAG1;
	frag_header.dgram_size = bit16;
	frag_header.garbage = 0;
	frag_header.garbage = frag_header.garbage | ((bit16>>8)&7);
	frag_header.dgram_tag = htons(packet_number);
	//printk(KERN_INFO"size = %u\n",(unsigned char *)skb->tail - data);
	memcpy(packet+size,&frag_header,frag_size); size += frag_size; req2 = size;
	memcpy(packet+size,dgram_offset,1); size += 1;
	memcpy(packet+size,HC1_dispatch,1); size += 1;
	memcpy(packet+size,&HC1encoded,HC1_size);  size += HC1_size;
	memcpy(packet+size,hoplimit,1); size += 1;
	if(HC1encoded.hc2){
		if(HC1encoded.nh==1){
			memcpy(packet+size,&udphdr,udp_size); size += udp_size;
			if(udphdr.s_port){
				port[0]=udp_header->source-0xf0b0;
				memcpy(packet+size,port,1); size += 1;
			}
			else{
				s_port_16 = htons(udp_header->source);
				memcpy(packet+size,&s_port_16,2); size +=2;
			}
			if(udphdr.d_port){
				port[0]=udp_header->dest-0xf0b0;
				memcpy(packet+size,port,1); size += 1;
			}
			else{
				d_port_16 = htons(udp_header->dest);
				memcpy(packet+size,&d_port_16,2); size +=2;
			}
			checksum_16 = htons(udp_header->check);
			memcpy(packet+size,&checksum_16,2); size +=2;
		}
		else if(HC1encoded.nh==3) {memcpy(packet+size,&tcphdr,tcp_size); size += tcp_size;} 
	}
	free_space = 81 - size;
	if(free_space<=(skb->tail-data)){
		memcpy(packet+size,data,free_space); 
		data +=free_space; 
		packet[req2]+=free_space;
		tot_size = size + free_space;
		grand = grand + free_space;
	}
	else {memcpy(packet+size,data,(skb->tail-data));
		tot_size = size + skb->tail-data;
		data = skb->tail; 
		grand = grand + skb->tail-data;
	}
	if(HC1encoded.nh==1&&bit16>255){
		//if(global){
		packet_number++;
		printk(KERN_INFO"\nPacket generated\n");
		printk(KERN_INFO"size %u\n",bit16);
		printk(KERN_INFO"FRAG1\n");
		for(int i=0;i<tot_size;i++){
			printk(KERN_INFO"%u:%x\n",i,packet[i]);
			//printk(KERN_INFO"tot %u grand %u \n17 %02x\n18 %02x\n",tot_size,grand,packet[17],packet[18]);
		}
		write_to_usb(packet,tot_size);
	//}
	}
			
	/*Subsequent packet Transmission*/
	/*Changinging Header field Fragment type*/
	frag_header.type = FRAGN;
	memcpy(packet+req1,&frag_header,frag_size);
	while(data<skb->tail){
		if(free_space<=(skb->tail-data)){
			memcpy(packet+size,data,free_space); 
			data +=free_space; 
			packet[req2]+=free_space;
			tot_size = size + free_space;
			grand = grand + free_space;
		}
		else {memcpy(packet+size,data,(skb->tail-data)); 
			tot_size = size + skb->tail-data; 
			grand = grand + skb->tail-data;
			data = skb->tail;
		}
		if(HC1encoded.nh==1&&bit16>255){
			//if(global){
			//printk(KERN_INFO"size %x\n",bit16);
			/*printk(KERN_INFO"FRAGN\n");
			for(int i=0;i<tot_size;i++){
				printk(KERN_INFO"%u:%x\n",i,packet[i]);
				//printk(KERN_INFO"tot %u grand %u \n17 %02x\n18 %02x\n",tot_size,grand,packet[17],packet[18]);
			}
			write_to_usb(packet,tot_size);*/
		//}
		}
	}
}
static void tcp_hc2(struct tcphdr *tcp_header){} //Futre Expansion of TCP header compression

unsigned int hook_func(void *priv,struct sk_buff *skb,const struct nf_hook_state *state){
	unsigned char *data=NULL;
	ip_header = (struct iphdr *)skb_network_header(skb);
	if(ip_header)
	if(ip_header->version==4){
		gen_mesh_header(0,0);
		ipv6_HC1(ip_header->protocol);
		if(HC1encoded.hc2==1){
			if(HC1encoded.nh==1){
				udp_header = (struct udphdr *)skb_transport_header(skb);
				udp_hc2(udp_header);
				data = (unsigned char *)udp_header + 8;
			}
			else if(HC1encoded.nh==3){
				tcp_header = (struct tcphdr *)skb_transport_header(skb);
				tcp_hc2(tcp_header);
				data = (unsigned char *)tcp_header + tcp_header->doff*4;
			}
			else {}//drop packets;
		}
		if(data){
			gen_packet(skb,data); 
		}
	}
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


static netdev_tx_t lowpan_xmit(struct sk_buff *skb,struct net_device *dev){
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
	#ifdef __LITTLE_ENDIAN_BITFIELD
		printk(KERN_INFO"Little endian\n");
	#endif
	#ifdef __BIG_ENDIAN_BITFIELD
		printk(KERN_INFO"Little endian\n");
	#endif
	nfho.hook = hook_func;
	nfho.hooknum = NF_INET_PRE_ROUTING;
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
MODULE_AUTHOR("Sathyam Panda");
