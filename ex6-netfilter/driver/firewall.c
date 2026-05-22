#include <linux/cdev.h>
#include <linux/device.h>
#include <linux/fs.h>
#include <linux/if.h>
#include <linux/in.h>
#include <linux/inet.h>
#include <linux/ip.h>
#include <linux/list.h>
#include <linux/module.h>
#include <linux/mutex.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/slab.h>

#define DEVICE_NAME "firewall"
#define LOG_PRFX "[firewall]: "
#define MOD_DEBUG(fmt, ...) pr_debug(LOG_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_INFO(fmt, ...) pr_info(LOG_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_WARN(fmt, ...) pr_warn(LOG_PRFX fmt "\n", ##__VA_ARGS__)
#define MOD_ERR(fmt, ...) pr_err(LOG_PRFX fmt "\n", ##__VA_ARGS__)

#define TYPE_INPUT "INPUT"
#define TYPE_OUTPUT "OUTPUT"

#define PROTO_ICMP "ICMP"
#define PROTO_TCP "TCP"
#define PROTO_UDP "UDP"

#define ACTION_ACCEPT "ACCEPT"
#define ACTION_DROP "DROP"

#define MAX_RULE_LEN                                                 \
  sizeof(ACTION_ACCEPT) + sizeof(PROTO_ICMP) + sizeof(TYPE_OUTPUT) + \
      INET_ADDRSTRLEN + 4

#define IOCTL_RESET _IO('f', 0)
#define IOCTL_ENABLE _IO('f', 1)
#define IOCTL_DISABLE _IO('f', 2)
#define IOCTL_SET_INTERFACE _IOW('f', 3, char[IFNAMSIZ])

enum action
{
  ACCEPT,
  DROP
};

enum protocol
{
  ICMP = IPPROTO_ICMP,
  TCP = IPPROTO_TCP,
  UDP = IPPROTO_UDP
};

enum firewall_packet_type
{
  INPUT,
  OUTPUT
};

struct rule
{
  struct list_head list;
  enum action action;
  enum protocol protocol;
  u32 ipv4_addr;
};

struct firewall_context
{
  enum firewall_packet_type cur_list_type;
  struct rule *cur_rule;
};

static dev_t firewall_dev;
static struct cdev *char_dev;
static struct class *device_class;

static struct nf_hook_ops nfho_input;
static struct nf_hook_ops nfho_output;

static struct list_head input;
static struct list_head output;

DEFINE_STATIC_SRCU(srcu_list);
static DEFINE_MUTEX(firewall_mutex);

static char target_interface[IFNAMSIZ] = "ens3";
static bool is_in_use = false;
static bool enable = true;

const char *get_proto(enum protocol proto)
{
  if (proto == ICMP)
    return PROTO_ICMP;
  if (proto == TCP)
    return PROTO_TCP;
  if (proto == UDP)
    return PROTO_UDP;
  return "";
}

static int parse_type(char *str, enum firewall_packet_type *type)
{
  if (!strncmp(str, TYPE_INPUT, strlen(TYPE_INPUT)))
  {
    *type = INPUT;
  }
  else if (!strncmp(str, TYPE_OUTPUT, strlen(TYPE_OUTPUT)))
  {
    *type = OUTPUT;
  }
  else
  {
    return -EINVAL;
  }
  return 0;
}

static int parse_protocol(char *str, enum protocol *proto)
{
  if (!strncmp(str, PROTO_ICMP, strlen(PROTO_ICMP)))
  {
    *proto = ICMP;
  }
  else if (!strncmp(str, PROTO_TCP, strlen(PROTO_TCP)))
  {
    *proto = TCP;
  }
  else if (!strncmp(str, PROTO_UDP, strlen(PROTO_UDP)))
  {
    *proto = UDP;
  }
  else
  {
    return -EINVAL;
  }
  return 0;
}

static int parse_action(char *str, enum action *type)
{
  if (!strncmp(str, ACTION_ACCEPT, strlen(ACTION_ACCEPT)))
  {
    *type = ACCEPT;
  }
  else if (!strncmp(str, ACTION_DROP, strlen(ACTION_DROP)))
  {
    *type = DROP;
  }
  else
  {
    return -EINVAL;
  }
  return 0;
}

static int parse_ipv4(char *str, u8 *res)
{
  if (!strncmp(str, "all", strlen("all")))
  {
    return !in4_pton("0.0.0.0", -1, res, -1, NULL);
  }
  else if (in4_pton(str, -1, res, -1, NULL))
  {
    return 0;
  }
  return -EINVAL;
}

static void firewall_reset(void)
{
  struct rule *pos, *n;
  MOD_DEBUG("Device reset");
  LIST_HEAD(dispose_list);

  mutex_lock(&firewall_mutex);
  list_splice_init(&input, &dispose_list);
  list_splice_init(&output, &dispose_list);
  enable = true;
  mutex_unlock(&firewall_mutex);

  synchronize_srcu(&srcu_list);

  list_for_each_entry_safe(pos, n, &dispose_list, list)
  {
    list_del(&pos->list);
    kfree(pos);
  }
}

static void free_lists(void) { firewall_reset(); }

static ssize_t device_read(struct file *file, char __user *buf, size_t size,
                           loff_t *offset)
{
  MOD_DEBUG("Device read");
  char kbuf[MAX_RULE_LEN] = {0};
  struct firewall_context *ctx = file->private_data;
  struct list_head *cur_list_head;
  size_t res_size = 0;
  int srcu_idx;

  if (!ctx)
    return -EINVAL;

  if (*offset > 0 && ctx->cur_rule == NULL)
  {
    return 0;
  }

  srcu_idx = srcu_read_lock(&srcu_list);

  cur_list_head = (ctx->cur_list_type == INPUT) ? &input : &output;

  if (ctx->cur_rule == NULL)
  {
    ctx->cur_rule = list_first_or_null_rcu(cur_list_head, struct rule, list);

    if (ctx->cur_rule == NULL)
    {
      if (ctx->cur_list_type == INPUT)
      {
        ctx->cur_list_type = OUTPUT;
        cur_list_head = &output;
        ctx->cur_rule =
            list_first_or_null_rcu(cur_list_head, struct rule, list);
        if (ctx->cur_rule == NULL)
        {
          srcu_read_unlock(&srcu_list, srcu_idx);
          return 0;
        }
      }
      else
      {
        srcu_read_unlock(&srcu_list, srcu_idx);
        return 0;
      }
    }
  }

  while (&ctx->cur_rule->list != cur_list_head)
  {
    size_t w_len = 0;

    if ((size - res_size) < MAX_RULE_LEN)
      break;

    w_len =
        snprintf(kbuf, MAX_RULE_LEN, "%s %d.%d.%d.%d %s %s\n",
                 ctx->cur_list_type == INPUT ? "INPUT" : "OUTPUT",
                 ((u8 *)&ctx->cur_rule->ipv4_addr)[0],
                 ((u8 *)&ctx->cur_rule->ipv4_addr)[1],
                 ((u8 *)&ctx->cur_rule->ipv4_addr)[2],
                 ((u8 *)&ctx->cur_rule->ipv4_addr)[3],
                 get_proto(ctx->cur_rule->protocol),
                 ctx->cur_rule->action == ACCEPT ? ACTION_ACCEPT : ACTION_DROP);

    if (copy_to_user(buf + res_size, kbuf, w_len))
    {
      srcu_read_unlock(&srcu_list, srcu_idx);
      return -EFAULT;
    }

    res_size += w_len;

    struct list_head *next_node = rcu_dereference_raw(ctx->cur_rule->list.next);
    if (next_node == cur_list_head)
    {
      if (ctx->cur_list_type == INPUT)
      {
        MOD_DEBUG("Read output list");
        ctx->cur_list_type = OUTPUT;
        cur_list_head = &output;
        ctx->cur_rule =
            list_first_or_null_rcu(cur_list_head, struct rule, list);
        if (ctx->cur_rule == NULL)
        {
          break;
        }
      }
      else
      {
        ctx->cur_rule = NULL;
        break;
      }
    }
    else
    {
      ctx->cur_rule = list_entry(next_node, struct rule, list);
    }
  }

  if (res_size > 0 && res_size < size)
  {
    if (put_user('\0', buf + res_size))
    {
      srcu_read_unlock(&srcu_list, srcu_idx);
      return -EFAULT;
    }
    res_size++;
  }

  *offset += res_size;

  srcu_read_unlock(&srcu_list, srcu_idx);
  return res_size;
}

static ssize_t device_write(struct file *, const char __user *buf, size_t size,
                            loff_t *)
{
  MOD_INFO("Device write");
  char kbuf[MAX_RULE_LEN] = {0};
  char type_str[sizeof(ACTION_ACCEPT)] = {0};
  char addr_str[INET_ADDRSTRLEN] = {0};
  char protocol_str[sizeof(ACTION_ACCEPT)] = {0};
  char action_str[sizeof(ACTION_ACCEPT)] = {0};
  struct rule *tmp_rule;
  enum firewall_packet_type type;
  u32 addr;
  enum protocol proto;
  enum action action;

  if (size > MAX_RULE_LEN)
  {
    return -EINVAL;
  }

  if (copy_from_user(kbuf, buf, size))
    return -EFAULT;

  kbuf[MAX_RULE_LEN - 1] = '\0';
  sscanf(kbuf, "%6s %16s %4s %6s", type_str, addr_str, protocol_str,
         action_str);

  MOD_INFO("Insert Rule:\n");
  MOD_INFO("\tType: %s\n", type_str);
  MOD_INFO("\tAddr: %s\n", addr_str);
  MOD_INFO("\tProtocol: %s\n", protocol_str);
  MOD_INFO("\tAction: %s\n", action_str);

  if (parse_type(type_str, &type))
    return -EINVAL;

  if (parse_ipv4(addr_str, (u8 *)&addr))
    return -EINVAL;

  if (parse_protocol(protocol_str, &proto))
    return -EINVAL;

  if (parse_action(action_str, &action))
    return -EINVAL;

  tmp_rule = kmalloc(sizeof(struct rule), GFP_KERNEL);
  if (!tmp_rule)
    return -ENOMEM;

  tmp_rule->action = action;
  tmp_rule->protocol = proto;
  tmp_rule->ipv4_addr = addr;

  mutex_lock(&firewall_mutex);
  if (type == INPUT)
  {
    list_add_tail_rcu(&tmp_rule->list, &input);
  }
  else if (type == OUTPUT)
  {
    list_add_tail_rcu(&tmp_rule->list, &output);
  }
  mutex_unlock(&firewall_mutex);

  return size;
}

static int device_open(struct inode *inode, struct file *file)
{
  struct firewall_context *ctx;
  MOD_DEBUG("Device open");

  mutex_lock(&firewall_mutex);
  if (is_in_use)
  {
    mutex_unlock(&firewall_mutex);
    return -EBUSY;
  }
  is_in_use = true;
  mutex_unlock(&firewall_mutex);

  ctx = kmalloc(sizeof(struct firewall_context), GFP_KERNEL);
  if (!ctx)
  {
    mutex_lock(&firewall_mutex);
    is_in_use = false;
    mutex_unlock(&firewall_mutex);
    return -ENOMEM;
  }

  ctx->cur_list_type = INPUT;
  ctx->cur_rule = NULL;

  file->private_data = ctx;

  return 0;
}

static int device_release(struct inode *inode, struct file *file)
{
  struct firewall_context *ctx = file->private_data;
  MOD_DEBUG("Device release");

  if (ctx)
  {
    kfree(ctx);
    file->private_data = NULL;
  }

  mutex_lock(&firewall_mutex);
  is_in_use = false;
  mutex_unlock(&firewall_mutex);

  return 0;
}

static long device_ioctl(struct file *file, unsigned int cmd,
                         unsigned long arg)
{
  switch (cmd)
  {
  case IOCTL_RESET:
    MOD_DEBUG("Got IOCTL_RESET");
    firewall_reset();
    break;
  case IOCTL_ENABLE:
    MOD_DEBUG("Got IOCTL_ENABLE");
    mutex_lock(&firewall_mutex);
    enable = true;
    mutex_unlock(&firewall_mutex);
    break;
  case IOCTL_DISABLE:
    MOD_DEBUG("Got IOCTL_DISABLE");
    mutex_lock(&firewall_mutex);
    enable = false;
    mutex_unlock(&firewall_mutex);
    break;
  case IOCTL_SET_INTERFACE:
  {
    char name[IFNAMSIZ] = {0};
    if (copy_from_user(name, (char __user *)arg, IFNAMSIZ))
      return -EFAULT;
    MOD_DEBUG("Got IOCTL_SET_INTERFACE with name %s", name);
    mutex_lock(&firewall_mutex);
    strncpy(target_interface, name, IFNAMSIZ - 1);
    target_interface[IFNAMSIZ - 1] = '\0';
    mutex_unlock(&firewall_mutex);
    break;
  }
  default:
    MOD_DEBUG("Got unknown IOCTL %u", cmd);
    return -ENOTTY;
  }
  return 0;
}

static unsigned int firewall_hook(void *priv, struct sk_buff *skb,
                                  const struct nf_hook_state *state)
{
  struct iphdr *ip_header;
  struct net_device *dev;
  const char *interface_name;
  bool is_input;
  __be32 packet_ip;
  struct rule *rule_entry;
  struct list_head *cur_list_head;
  unsigned int verdict = NF_ACCEPT;
  int srcu_idx;

  if (!enable)
  {
    MOD_DEBUG("Filter disabled");
    return NF_ACCEPT;
  }

  if (state->hook == NF_INET_LOCAL_IN)
  {
    is_input = true;
    dev = state->in;
  }
  else if (state->hook == NF_INET_LOCAL_OUT)
  {
    is_input = false;
    dev = state->out;
  }
  else
  {
    MOD_DEBUG("Packet is not out or input");
    return NF_ACCEPT;
  }

  if (!dev)
  {
    MOD_DEBUG("Buffer skb does not contain device");
    return NF_ACCEPT;
  }

  interface_name = dev->name;
  if (strcmp(interface_name, target_interface) != 0)
  {
    MOD_DEBUG("Packet does not correspond to the target interface");
    return NF_ACCEPT;
  }

  ip_header = ip_hdr(skb);
  if (!ip_header)
  {
    MOD_DEBUG("Packet does not contain ip header");
    return NF_ACCEPT;
  }

  MOD_DEBUG("Processing packet");
  packet_ip = is_input ? ip_header->saddr : ip_header->daddr;
  cur_list_head = is_input ? &input : &output;

  srcu_idx = srcu_read_lock(&srcu_list);
  list_for_each_entry_rcu(rule_entry, cur_list_head, list)
  {
    u32 all_ip;
    in4_pton("0.0.0.0", -1, (u8 *)&all_ip, -1, NULL);

    if (rule_entry->protocol != ip_header->protocol)
      continue;
    if (!(rule_entry->ipv4_addr == all_ip) &&
        rule_entry->ipv4_addr != packet_ip)
      continue;

    verdict = (rule_entry->action == ACCEPT) ? NF_ACCEPT : NF_DROP;
    break;
  }
  srcu_read_unlock(&srcu_list, srcu_idx);
  MOD_INFO(
      "Got packet: type (%s) addr (%d.%d.%d.%d) protocol(%s) decision (%s)\n",
      is_input ? TYPE_INPUT : TYPE_OUTPUT, ((u8 *)&packet_ip)[0],
      ((u8 *)&packet_ip)[1], ((u8 *)&packet_ip)[2], ((u8 *)&packet_ip)[3],
      ip_header->protocol == TCP
          ? PROTO_TCP
          : (ip_header->protocol == UDP ? PROTO_UDP : PROTO_ICMP),
      verdict == NF_ACCEPT ? "ACCEPT" : "DROP");

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

static int __init firewall_init(void)
{
  MOD_INFO("Initializing...");

  if (alloc_chrdev_region(&firewall_dev, 0, 1, DEVICE_NAME))
  {
    return -ENOMEM;
  }
  char_dev = cdev_alloc();
  if (!char_dev)
  {
    goto INIT_EXIT_CDEV;
  }

  cdev_init(char_dev, &fops);
  if (cdev_add(char_dev, firewall_dev, 1))
  {
    goto INIT_EXIT_CDEV;
  }

  device_class = class_create(THIS_MODULE, DEVICE_NAME);
  if (!device_create(device_class, NULL, firewall_dev, NULL, DEVICE_NAME))
  {
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

  INIT_LIST_HEAD_RCU(&input);
  INIT_LIST_HEAD_RCU(&output);

  return 0;

INIT_EXIT_CLASS:
  class_destroy(device_class);
INIT_EXIT_CDEV:
  cdev_del(char_dev);
  unregister_chrdev_region(firewall_dev, 1);

  return -ENOMEM;
}

static void __exit firewall_exit(void)
{
  MOD_INFO("Module exit");
  nf_unregister_net_hook(&init_net, &nfho_input);
  nf_unregister_net_hook(&init_net, &nfho_output);

  device_destroy(device_class, firewall_dev);
  class_destroy(device_class);
  cdev_del(char_dev);
  unregister_chrdev_region(firewall_dev, 1);
  free_lists();
}

module_init(firewall_init);
module_exit(firewall_exit);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("Andrei Gavrilov");
MODULE_DESCRIPTION("IPv4 custom firewall");
