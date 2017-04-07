#include <linux/init.h>             // Macros used to mark up functions e.g., __init __exit
#include <linux/module.h>           // Core header for loading LKMs into the kernel
#include <linux/kernel.h>           // Contains types, macros, functions for the kernel
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>

MODULE_LICENSE("GPL");              
MODULE_AUTHOR("Sathyam Panda");     
MODULE_DESCRIPTION("A simple Linux driver");
MODULE_VERSION("1.0");              

static struct nf_hook_ops nfho;
static struct net_device *lowpan,*temp;
static struct net netp;
unsigned int hook_func(void *priv,struct sk_buff *skb,const struct nf_hook_state *state)
{
	skb->dev = lowpan;
	printk(KERN_INFO"Device = %s\n",skb->dev->name);
	return NF_ACCEPT;
}
static int lowpan_open(struct net_device *dev)
{
	printk(KERN_INFO"6lowpan0 is up and running\n");
	netif_start_queue(dev);
	return 0;
}
static int lowpan_close(struct net_device *dev)
{
	printk(KERN_INFO"6lowpan0 is stopped\n");
	netif_stop_queue(dev);
	return 0;
}
static netdev_tx_t lowpan_xmit(struct sk_buff *skb,struct net_device *dev)
{
	printk(KERN_INFO"Freeing skb\n");
	//dev_kfree_skb(skb);
	/*temp = dev;
	temp = next_net_device_rcu(temp);
	if(temp)
		printk(KERN_INFO"Device found = %s\n",temp->name);*/
	temp = dev_get_by_name_rcu(&net,"wlan0");
	if(temp)
		printk(KERN_INFO"Device found = %s\n",temp->name);
	return NETDEV_TX_OK;
}

static const struct net_device_ops dev_ops = {
	.ndo_open = lowpan_open,
	.ndo_stop = lowpan_close,
	.ndo_start_xmit = lowpan_xmit
};
static int lowpan_init(struct net_device *dev)
{
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
	lowpan = alloc_netdev(10,"6lowpan0",0,(void *)lowpan_init);
	if(!register_netdev(lowpan)) 
		printk(KERN_INFO"%s is registered\n",lowpan->name);
	return 0;   
}

static void firstmod_exit(void){
     nf_unregister_hook(&nfho);
     unregister_netdev(lowpan);
     printk(KERN_INFO"%s is unregistered\n",lowpan->name);;
     free_netdev(lowpan);
}
module_init(firstmod_init);
module_exit(firstmod_exit);