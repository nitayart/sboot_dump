#include <stdlib.h>
#include <stdbool.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>


#define DEBUG

#define USB_CLASS_CDC_DATA 0x0A
#define ID_SAMSUNG 0x04e8
#define ID_GALAXY 0x685d

#define DL_FLAG 1
#define UL_FLAG 2
#define GET_PIT 4
#define RESUME 8
#define PROBE 16
#define TRIGGER 32

#ifdef DEBUG
	#define debug(s, ...) printf(s "\n", ##__VA_ARGS__)
#else
	#define debug(s, ...)
#endif

struct device_data {
	struct libusb_device *samsung_device;
	struct libusb_device_handle *device_handle;
	int interface_index;
	int alt_setting_index;
	int in_endpoint;
	int out_endpoint;
};


int grepdev(libusb_device *dev);
int initialise_device(struct device_data* dev_data);
// int do_transaction(struct device_data* dev_data, unsigned char *send_buf, size_t send_size, unsigned char* recv_buf, size_t recv_size, int send_empty);
int do_transaction(struct device_data* dev_data, unsigned char *send_buf, size_t send_size, unsigned char* recv_buf, size_t recv_size, int send_empty);

