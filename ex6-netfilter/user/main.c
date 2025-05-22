#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <assert.h>
#include <sys/ioctl.h>

#define DEVICE "/dev/firewall"
#define TYPE_INPUT "INPUT"
#define TYPE_OUTPUT "OUTPUT"

#define PROTO_ICMP "ICMP"
#define PROTO_TCP "TCP"
#define PROTO_UDP "UDP"

#define ACTION_ACCEPT "ACCEPT"
#define ACTION_DROP "DROP"

#define IFNAMSIZ 16
#define MAX_RULE_LEN sizeof(ACTION_ACCEPT) + sizeof (PROTO_ICMP) \
			+ sizeof(TYPE_OUTPUT) + IFNAMSIZ + 4

#define IOCTL_RESET _IO('f', 0)
#define IOCTL_ENABLE _IO('f', 1)
#define IOCTL_DISABLE _IO('f', 2)
#define IOCTL_SET_INTERFACE _IOW('f', 3, char[IFNAMSIZ])

#define TEST_INPUT_1 "OUTPUT 254.2.3.2 TCP DROP\n"
#define TEST_INPUT_2 "INPUT 254.2.3.2 ICMP DROP\n"
#define TEST_INPUT_3 "OUTPUT 254.2.3.2 TCP ACCEPT\n"
#define TEST_INPUT_4 "INPUT 254.2.3.2 UDP ACCEPT\n"

void test_read_empty() {
	int fd;
	char buf[MAX_RULE_LEN];
	fd = open(DEVICE, O_RDWR);

	assert(fd >= 0);
	assert(read(fd, buf, MAX_RULE_LEN) == 0);
	
	close(fd);
}

void test_read() {
	int fd;
	char res[] = TEST_INPUT_2  TEST_INPUT_4 TEST_INPUT_1 TEST_INPUT_3;
	char buf[strlen(res)];
	char tmp_buf[strlen(res)];
	fd = open(DEVICE, O_RDWR);

	assert(fd >= 0);
	while(read(fd, tmp_buf, strlen(res)) > 0) {
		strcat(buf, tmp_buf);
	}
	assert(strlen(buf) == strlen(res));
	assert(strcmp(buf, res) == 0);
	
	close(fd);
}

void test_write() {
	int fd;
	char buf[MAX_RULE_LEN];
	fd = open(DEVICE, O_RDWR);

	assert(fd >= 0);
	assert(write(fd, TEST_INPUT_1, strlen(TEST_INPUT_1)) == strlen(TEST_INPUT_1));
	assert(write(fd, TEST_INPUT_2, strlen(TEST_INPUT_2)) == strlen(TEST_INPUT_2));
	assert(write(fd, TEST_INPUT_3, strlen(TEST_INPUT_3)) == strlen(TEST_INPUT_3));
	assert(write(fd, TEST_INPUT_4, strlen(TEST_INPUT_4)) == strlen(TEST_INPUT_4));

	close(fd);
}

void test_ioctl_reset() {
	int fd;
    
	fd = open(DEVICE, O_RDWR);
	assert(fd >= 0);
	assert(ioctl(fd, IOCTL_RESET, NULL) == 0);
	close(fd);
}

void test_ioctl_enable() {
	int fd;
    
	fd = open(DEVICE, O_RDWR);
	assert(fd >= 0);
	assert(ioctl(fd, IOCTL_ENABLE, NULL) == 0);
	close(fd);
}

void test_ioctl_disable() {
	int fd;
    
	fd = open(DEVICE, O_RDWR);
	assert(fd >= 0);
	assert(ioctl(fd, IOCTL_DISABLE, NULL) == 0);
	close(fd);
}

void test_ioctl_interface() {
	int fd;
	char name1[IFNAMSIZ] = "eth0";
	char name2[IFNAMSIZ] = "ens3";
	fd = open(DEVICE, O_RDWR);
	assert(fd >= 0);
	assert(ioctl(fd, IOCTL_SET_INTERFACE, name1) == 0);
	assert(ioctl(fd, IOCTL_SET_INTERFACE, name2) == 0);
	close(fd);
}

int main() {
	test_ioctl_reset();
	test_read_empty();
	test_write();
	test_read();
	// Next should be checked by dmesg
	test_ioctl_reset();
	test_ioctl_disable();
	test_ioctl_enable();
	test_ioctl_interface();
	return 0;
}