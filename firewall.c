/*
 * firewall.c
 *
 * A kernel module which implements a firewall to drop packets 
 * for icmp, ssh and http requests
 *
 * Compile using make. Use insmod firewall.ko to insert the module
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/ip.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/skbuff.h>
#include <linux/udp.h>

#define PRIVATE_INTERFACE "eth0"
#define WEB_SERVER_IP     "\xC0\xA8\x04\x01" //192.168.4.1
#define SSH_PORT          "\x00\x16"
#define HTTP_PORT         "\x00\x50"

static struct nf_hook_ops netfilter_ops_pre;
struct sk_buff *sock_buff;
struct udphdr *udp_header;

unsigned int pre_hook(unsigned int hooknum,
                       struct sk_buff *skb,
                       const struct net_device *in,
                       const struct net_device *out,
                       int (*okfn) (struct sk_buff *))
{
	char dest_ip[17];
	sock_buff = skb;
	if(!sock_buff){ return NF_ACCEPT; }
	if(!(ip_hdr(sock_buff))){ return NF_ACCEPT; }
	udp_header = (struct udphdr *)(sock_buff->data + (( (ip_hdr(sock_buff))->ihl ) * 4));
	snprintf(dest_ip, 16, "%pI4", &(ip_hdr(sock_buff))->daddr);

	if(in)
	{
		/* Rule for ICMP requests */
		if(!(strcmp(in->name, PRIVATE_INTERFACE) == 0) &&
		    !((ip_hdr(sock_buff))->daddr == *(unsigned int *)WEB_SERVER_IP) && 
		    (( (ip_hdr(sock_buff))->protocol ) != 1))
		{ 
			printk("Dropped. Cause: ICMP, from interface %s, destination= %s\n", in->name, dest_ip);
			return NF_DROP;
		}

		/* Rule for ssh connections */
		if(!(strcmp(in->name, PRIVATE_INTERFACE) == 0) && 
		    (udp_header->dest == *(unsigned short *)SSH_PORT))
		{ 
			printk("Dropped. Cause: SSH, from interface %s, destination= %s\n", in->name, dest_ip);
			return NF_DROP;
		}

		/* Rule for HTTP requests */
		if(!(strcmp(in->name, PRIVATE_INTERFACE) == 0) &&
		    !((ip_hdr(sock_buff))->daddr == *(unsigned int *)WEB_SERVER_IP) && 
		    (udp_header->dest == *(unsigned short *)HTTP_PORT))
		{ 
			printk("Dropped. Cause: HTTP, from interface %s, destination= %s\n", in->name, dest_ip);
			return NF_DROP;
		}
	}
	else //if (in)
	{
		printk("Error:Input interface not initialized\n");
	}

	/* Accept all other packets */
	return NF_ACCEPT;
}

int init_module()
{
	netfilter_ops_pre.hook       =     pre_hook;
	netfilter_ops_pre.pf         =     PF_INET;
	netfilter_ops_pre.hooknum    =     NF_INET_PRE_ROUTING;
	netfilter_ops_pre.priority   =     NF_IP_PRI_FIRST;

	nf_register_hook(&netfilter_ops_pre);

	return 0;
}

void cleanup_module()
{
	nf_unregister_hook(&netfilter_ops_pre);
}