#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/list.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include "firewall.h"

#define DEVICE_NAME "firewall"
#define LOG_PRFX "[firewall]: "
#define MOD_DEBUG(fmt, ...) pr_debug(LOG_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_INFO(fmt, ...) pr_info(LOG_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_WARN(fmt, ...) pr_warn(LOG_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_ERR(fmt, ...) pr_err(LOG_PRFX fmt "\n", ##__VA_ARGS__)


struct firewall_rule {
	struct list_head list;
	enum protocol protocol;
	enum action action;
	u32 ipv4_addr;
};

static dev_t firewall_dev;
static struct cdev *char_dev;
static struct class *device_class;

static DEFINE_SPINLOCK(firewall_lock); // nethook requires spin lock
static struct list_head input_rules;
static struct list_head output_rules;

/* Support only one user */
static char target_interface[IFNAMSIZ] = "ens3";
static bool is_in_use = false;
static bool enable = true;
static enum firewall_packet_type cur_type = INPUT;
static struct firewall_rule *cur_entry = NULL;

static struct nf_hook_ops nfho_input;
static struct nf_hook_ops nfho_output;


static ssize_t device_read(struct file *file, char __user *buf,
			   size_t size, loff_t *) {
	MOD_DEBUG("Device read");
	char kbuf[MAX_RULE_LEN];
	struct list_head *cur_list_head = (cur_type == INPUT) ? 
					  &input_rules : &output_rules;
	size_t ret_size = 0;
	if (cur_entry == NULL) cur_entry = list_first_entry(cur_list_head, 
							    typeof(*cur_entry), 
							    list);
	spin_lock(&firewall_lock);
	list_for_each_entry_from(cur_entry, cur_list_head, list) {
		size_t w_len = 0;

		if ((size - ret_size) < MAX_RULE_LEN) break;
		
		w_len = snprintf(kbuf, MAX_RULE_LEN, "%s %d.%d.%d.%d %s %s\n", 
			 cur_type == INPUT ? "INPUT" : "OUTPUT",
			 ((u8 *)&cur_entry->ipv4_addr)[0],
			 ((u8 *)&cur_entry->ipv4_addr)[1],
			 ((u8 *)&cur_entry->ipv4_addr)[2],
			 ((u8 *)&cur_entry->ipv4_addr)[3],
			 get_proto(cur_entry->protocol),
			 cur_entry->action == ACCEPT ? ACTION_ACCEPT :
			 			       ACTION_DROP);
		if (copy_to_user(buf, kbuf, w_len)) return -EFAULT;
		
		buf += w_len;
		ret_size += w_len;

		if (list_entry_is_head(list_next_entry(cur_entry, list), 
				       cur_list_head, list) &&
		    cur_type == INPUT) {
			MOD_DEBUG("Read output list");
			cur_type = OUTPUT;
			cur_list_head = &output_rules;
			cur_entry = list_first_entry(cur_list_head, 
						     typeof(*cur_entry), 
						     list);
			break;
		}
	}
	spin_unlock(&firewall_lock);

	return ret_size;
}

static int parse_type(char *str, enum firewall_packet_type *type) {
	if (!strncmp(str, TYPE_INPUT, strlen(TYPE_INPUT))) {
		*type = INPUT;
	} else if (!strncmp(str, TYPE_OUTPUT, strlen(TYPE_OUTPUT))) {
		*type = OUTPUT;
	} else {
		return -EINVAL;
	}
	return 0;
}

static int parse_protocol(char *str, enum protocol *proto) {
	if (!strncmp(str, PROTO_ICMP, strlen(PROTO_ICMP))) {
		*proto = ICMP;
	} else if (!strncmp(str, PROTO_TCP, strlen(PROTO_TCP))) {
		*proto = TCP;
	} else if (!strncmp(str, PROTO_UDP, strlen(PROTO_UDP))) {
		*proto = UDP;
	} else {
		return -EINVAL;
	}
	return 0;
}

static int parse_action(char *str, enum action *type) {
	if (!strncmp(str, ACTION_ACCEPT, strlen(ACTION_ACCEPT))) {
		*type = INPUT;
	} else if (!strncmp(str, ACTION_DROP, strlen(ACTION_DROP))) {
		*type = OUTPUT;
	} else {
		return -EINVAL;
	}
	return 0;
}

static int parse_ipv4(char *str, u8 *res) {
	if (!strncmp(str, "all", strlen("all"))) {
		return !in4_pton("0.0.0.0", -1, res, -1, NULL);
	} else if (in4_pton(str, -1, res, -1, NULL)) {
		return 0;
	}
	return -EINVAL;
}

static ssize_t device_write(struct file *, const char __user *buf,
		     size_t size, loff_t *) {
	char kbuf[MAX_RULE_LEN];
	struct firewall_rule *rule;
	enum firewall_packet_type type;
	enum protocol proto;
	enum action action;
	u32 ipv4_addr;
	if (size > MAX_RULE_LEN) {
		return -EINVAL;
	}

	if (copy_from_user(kbuf, buf, size))
		return -EFAULT;

	char *cur, *next;
	next = kbuf;
	cur = strsep(&next, " ");
	int i = 0, ret = 0;
	while (cur != NULL) {
		switch (i)
		{
		case 0:
			ret = parse_type(cur, &type);
			if (!ret)
				MOD_DEBUG("Device write type: %d", type);
			break;
		case 1:
			ret = parse_ipv4(cur, (u8 *)(&ipv4_addr));
			if (!ret)
				MOD_DEBUG("Device write ipv4: %s", cur);
			break;
		case 2:
			ret = parse_protocol(cur, &proto);
			if (!ret)
				MOD_DEBUG("Device write proto: %d", proto);
			break;
		case 3:
			ret = parse_action(cur, &action);
			if (!ret)
				MOD_DEBUG("Device write action: %d", action);
			break;
		default:
			return -EINVAL;
		}
		if (ret) return -EINVAL;
		i += 1;
		cur = strsep(&next, " ");
		if (i > 3) break;
	}
	rule = kmalloc(sizeof(struct firewall_rule), GFP_KERNEL);

	if (!rule) return -ENOMEM;

	rule->action = action;
	rule->protocol = proto;
	rule->ipv4_addr = ipv4_addr;

	spin_lock(&firewall_lock);
	if (type == INPUT)
		list_add_tail(&rule->list, &input_rules);
	else if (type == OUTPUT)
		list_add_tail(&rule->list, &output_rules);
	spin_unlock(&firewall_lock);

	return size;
}

static int device_open(struct inode *, struct file *) {
	MOD_DEBUG("Device open");
	if (is_in_use) return -EBUSY;
	is_in_use = true;
	cur_type = INPUT;
	cur_entry = NULL;
	return 0;
}

static int device_release(struct inode *, struct file *) {
	MOD_DEBUG("Device release");
	cur_type = INPUT;
	cur_entry = NULL;
	is_in_use = false;
	return 0;
}

static void firewall_reset(void) {
	struct firewall_rule *pos;
	struct firewall_rule *n;
	spin_lock(&firewall_lock);

	list_for_each_entry_safe(pos, n, &input_rules, list) {
		list_del(&pos->list);
		kfree(pos);
	}

	list_for_each_entry_safe(pos, n, &output_rules, list) {
		list_del(&pos->list);
		kfree(pos);
	}

	enable = true;
	spin_unlock(&firewall_lock);

}

static long device_ioctl(struct file *file, unsigned int cmd,
			 unsigned long arg) {
	switch (cmd)
	{
	case IOCTL_RESET:
		MOD_DEBUG("Got IOCTL_RESET");
		firewall_reset();
		break;
	case IOCTL_ENABLE:
		MOD_DEBUG("Got IOCTL_ENABLE");
		spin_lock(&firewall_lock);
		enable = true;
		spin_unlock(&firewall_lock);
		break;
	case IOCTL_DISABLE:
		MOD_DEBUG("Got IOCTL_DISABLE");
		spin_lock(&firewall_lock);
		enable = false;
		spin_unlock(&firewall_lock);
		break;
	case IOCTL_SET_INTERFACE:
		char name[IFNAMSIZ] = {0};
		if (copy_from_user(name, (char __user *)arg, IFNAMSIZ))
			return -EFAULT;
		MOD_DEBUG("Got IOCTL_SET_INTERFACE with name %s", name);
		spin_lock(&firewall_lock);
		strlcpy(target_interface, name, IFNAMSIZ);
		spin_unlock(&firewall_lock);
		break;
	default:
		MOD_DEBUG("Got unknown IOCTL %u", cmd);
		return -ENOTTY;
	}
	return 0;
}

static unsigned int firewall_hook(void *priv, struct sk_buff *skb,
				  	const struct nf_hook_state *state) {
	struct iphdr *ip_header;
	struct net_device *dev;
	const char *interface_name;
	bool is_input;
	__be32 packet_ip;

	spin_lock(&firewall_lock);
	if (!enable) {
		spin_unlock(&firewall_lock);
		return NF_ACCEPT;
	}

	dev = skb->dev;
	if (!dev) {
		spin_unlock(&firewall_lock);
		return NF_ACCEPT;
	}

	interface_name = dev->name;
	if (strcmp(interface_name, target_interface) != 0) {
		spin_unlock(&firewall_lock);
		return NF_ACCEPT;
	}

	if (state->hook == NF_INET_LOCAL_IN) {
        	is_input = true;
	} else if (state->hook == NF_INET_LOCAL_OUT) {
		is_input = false;
	} else {
		spin_unlock(&firewall_lock);
		return NF_ACCEPT;
	}

	ip_header = ip_hdr(skb);
	if (!ip_header) {
		spin_unlock(&firewall_lock);
		return NF_ACCEPT;
	}

	packet_ip = is_input ? ip_header->saddr : ip_header->daddr;

	struct firewall_rule *rule;
	struct list_head *cur_list_head = is_input ? 
					  &input_rules : &output_rules;
	unsigned int verdict = NF_ACCEPT;
	list_for_each_entry(rule, cur_list_head, list) {
		u32 all_ip;
		in4_pton("0.0.0.0", -1, (u8 *)&all_ip, -1, NULL);
		if (rule->protocol != ip_header->protocol)
			continue;
		if (!(rule->ipv4_addr == all_ip) && rule->ipv4_addr != packet_ip)
			continue;

		verdict = (rule->action == ACCEPT) ? NF_ACCEPT : NF_DROP;
		break;
	}
	spin_unlock(&firewall_lock);

	return verdict;
}

static struct file_operations fops = {
	.open = device_open,
	.release = device_release,
	.unlocked_ioctl = device_ioctl,
	.read = device_read,
	.write = device_write,
	.owner = THIS_MODULE,
};

static int __init hello_init(void)
{
	MOD_INFO("Initializing...");
	INIT_LIST_HEAD(&input_rules);
	INIT_LIST_HEAD(&output_rules);
	if (alloc_chrdev_region(&firewall_dev, 0, 1, DEVICE_NAME)) {
		return -ENOMEM;
	}
	char_dev = cdev_alloc();
	if (!char_dev) {
		goto INIT_EXIT_CDEV;
	}

	cdev_init(char_dev, &fops);
	if (cdev_add(char_dev, firewall_dev, 1)) {
		goto INIT_EXIT_CDEV;
	}

	device_class = class_create(THIS_MODULE, DEVICE_NAME);
	if(!device_create(device_class, NULL, firewall_dev, NULL, DEVICE_NAME)) {
		goto INIT_EXIT_CLASS;
	}

	nfho_input.hook = firewall_hook;
	nfho_input.pf = NFPROTO_IPV4;
	nfho_input.hooknum = NF_INET_LOCAL_IN;
	nfho_input.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfho_input);

	nfho_output.hook = firewall_hook;
	nfho_output.pf = NFPROTO_IPV4;
	nfho_output.hooknum = NF_INET_LOCAL_OUT;
	nfho_output.priority = NF_IP_PRI_FIRST;
	nf_register_net_hook(&init_net, &nfho_output);

	return 0;

INIT_EXIT_CLASS:
	class_destroy(device_class);
INIT_EXIT_CDEV:
	cdev_del(char_dev);
	unregister_chrdev_region(firewall_dev, 1);

	return -ENOMEM;
}

static void __exit hello_exit(void)
{
	MOD_INFO("Module exit");
	nf_unregister_net_hook(&init_net, &nfho_input);
    	nf_unregister_net_hook(&init_net, &nfho_output);
	
	device_destroy(device_class, firewall_dev);
	class_destroy(device_class);
	cdev_del(char_dev);
	unregister_chrdev_region(firewall_dev, 1);
}

module_init(hello_init);
module_exit(hello_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrei Gavrilov");
MODULE_DESCRIPTION("IPv4 custom firewall");