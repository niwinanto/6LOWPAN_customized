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

static struct nf_hook_ops nfho;
static struct net_device *lowpan,*ethdev;
static int flag=0;
static struct file *rc;
//static struct net *net;
unsigned int hook_func(void *priv,struct sk_buff *skb,const struct nf_hook_state *state){
if(skb->dev)
	{
	if(flag==0){ethdev = skb->dev; printk("Device assigned =%s\n",ethdev->name);}
	else if(flag==1)
	{
	/*	printk(KERN_INFO"flag set skb->dev = %u ethdev = %u ethdev->ndo_start_xmit = %u\n"
			,(unsigned int)skb->dev
			,(unsigned int)ethdev
			,(unsigned int)ethdev->netdev_ops->ndo_start_xmit);*/
		skb->dev = lowpan;
	//	printk(KERN_INFO"Flag set New Device = %s\n",skb->dev->name);
		return NF_ACCEPT;
	}
	if(!strcmp(ethdev->name,"wlan0"))
	{
		skb->dev = lowpan;
		printk(KERN_INFO"ethdev set Device = %s\n",skb->dev->name);
		flag=1;
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

    printk(KERN_INFO"Writing serial device\n");
    struct file * const fileP = rc;

    if (!fileP->f_op)
        printk("%s: File has no file operations registered!",__FUNCTION__);
    else {
        ssize_t (*writeOp)(struct file *, const char *, size_t, loff_t *) = fileP->f_op->write;

        if (writeOp == NULL)
            printk("%s: File has no write operation registered!",__FUNCTION__);
        else {
            ssize_t rl;
            mm_segment_t oldfs;
            const char buffer[] = "This is the test data\n";


            fileP->f_pos = 0;
            /* As the write operation for this file gets the
               the data to write from the user's address space (fs),
               we must switch fs to be the kernel address space
               while we do this write, and then restore it afterwards.
               */
            oldfs = get_fs();
            set_fs(get_ds());

            rl = writeOp(fileP, buffer, sizeof(buffer), &fileP->f_pos);

            set_fs(oldfs);

            if (rl < 0) {
                printk("%s: filesystem driver's write() operation for "
                        "returned errno %d. ", __FUNCTION__, (int)-rl);
            }
            else if (rl != sizeof(buffer)) {
                printk("%s: write returned only %d bytes instead of %d.\n",__FUNCTION__, (int)rl, (int)sizeof(buffer));
            } else
                printk("%s: write was successful.\n", __FUNCTION__);
        }

    }

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
