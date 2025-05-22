#include <linux/inet.h>
#include <linux/if.h>

#define TYPE_INPUT "INPUT"
#define TYPE_OUTPUT "OUTPUT"

#define PROTO_ICMP "ICMP"
#define PROTO_TCP "TCP"
#define PROTO_UDP "UDP"

#define ACTION_ACCEPT "ACCEPT"
#define ACTION_DROP "DROP"

enum action {
	ACCEPT,
	DROP
};

enum protocol {
	ICMP = IPPROTO_ICMP,
	TCP = IPPROTO_TCP,
	UDP = IPPROTO_UDP
};

enum firewall_packet_type {
	INPUT,
	OUTPUT
};

const char *get_proto(enum protocol proto) {
	if (proto == ICMP) return PROTO_ICMP;
	if (proto == TCP) return PROTO_TCP;
	if (proto == UDP) return PROTO_UDP;
	return "";
}

#define MAX_RULE_LEN sizeof(ACTION_ACCEPT) + sizeof (PROTO_ICMP) \
			+ sizeof(TYPE_OUTPUT) + INET_ADDRSTRLEN	+ 4

#define IOCTL_RESET _IO('f', 0)
#define IOCTL_ENABLE _IO('f', 1)
#define IOCTL_DISABLE _IO('f', 2)
#define IOCTL_SET_INTERFACE _IOW('f', 3, char[IFNAMSIZ])