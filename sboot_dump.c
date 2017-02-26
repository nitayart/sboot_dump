#include <stdio.h>
#include <string.h>
#include <libusb.h>
#include <stdbool.h>
#include <unistd.h>
#include "sboot_dump.h"
#include "hexdump.h"


int do_transaction(struct device_data* dev_data, unsigned char *send_buf, size_t send_size, unsigned char* recv_buf, size_t recv_size, int send_empty) {

	/* 0x65 is pit request header
	 * 0x01 is dump request */

	unsigned char send_packet[1024];
	int result, transferred_len, i;

	memset(send_packet, 0, 1024);
	memcpy(send_packet, send_buf, send_size);

	debug("[*] About to send packet:");
	// hexdump_log(send_packet, 1024);

	if (send_empty) {
		result = libusb_bulk_transfer(dev_data->device_handle, dev_data->out_endpoint, 0, 0, &transferred_len, 3000);
		if (result != LIBUSB_SUCCESS) {
			debug("[-] Failed to send empty packet before send. Result: %d", result);
		}
	}

	result = libusb_bulk_transfer(dev_data->device_handle, dev_data->out_endpoint, send_packet, 1024, &transferred_len, 1000);
	if (result != LIBUSB_SUCCESS) {
		debug("[-] Failed to send packet");
		return -1;
	}

	if (send_empty) {
		result = libusb_bulk_transfer(dev_data->device_handle, dev_data->out_endpoint, 0, 0, &transferred_len, 3000);
		if (result != LIBUSB_SUCCESS) {
			debug("[-] Failed to send empty packet after send. Result: %d", result);
		}
	}

	if (send_empty) {
		result = libusb_bulk_transfer(dev_data->device_handle, dev_data->in_endpoint, 0, 0, &transferred_len, 3000);
		if (result != LIBUSB_SUCCESS) {
			debug("[-] Failed to receive empty packet, result: %d", result);
		}
	}

	result = libusb_bulk_transfer(dev_data->device_handle, dev_data->in_endpoint, recv_buf, recv_size, &transferred_len, 3000);
	if (result != LIBUSB_SUCCESS) {
		debug("[-] Failed to receive response packet, result: %d", result);
		return -1;
	}

	debug("[*] Received response packet:");
	// hexdump_log(recv_buf, transferred_len);
	return 0;
}


int do_upload(struct device_data* dev_data, unsigned char *start_addr, unsigned char *end_addr, bool do_hexdump) {
	int result, transferred_len;

	unsigned char *dataxfer_send_packet = "DaTaXfEr\0";
	unsigned char *preamble_send_packet = "PrEaMbLe\0";
	unsigned char *recv_buf;
	size_t buf_size = ((unsigned int) strtol(end_addr, NULL, 16)) - ((unsigned int) strtol(start_addr, NULL, 16));
	int fd, ret = -1;

	debug("[*] Initialising upload protocol, preparing to dump from 0x%s to 0x%s", start_addr, end_addr);

	if (buf_size > 0x80000) {
		debug("[-] Upload Mode supports dump size of up to 0x80000");
		return ret;
	}

	recv_buf = malloc(buf_size);

	if (!recv_buf) {
		debug("[-] Failed to allocated recv_buf");
		return ret;
	}

	result = do_transaction(dev_data, preamble_send_packet, strlen(preamble_send_packet) + 1, recv_buf, buf_size, 0);

	if (result) {
		debug("[-] Failed to send preamble packet");
		goto fail;
	}

	memset(recv_buf, 0, buf_size);

	result = do_transaction(dev_data, start_addr, strlen(start_addr) + 1, recv_buf, buf_size, 0);

	if (result) {
		debug("[-] Failed to send start address packet");
		goto fail;
	}

	memset(recv_buf, 0, buf_size);

	result = do_transaction(dev_data, end_addr, strlen(end_addr) + 1, recv_buf, buf_size, 0);

	if (result) {
		debug("[-] Failed to send end address packet");
		goto fail;
	}

	memset(recv_buf, 0, buf_size);

	result = do_transaction(dev_data, dataxfer_send_packet, strlen(dataxfer_send_packet) + 1, recv_buf, buf_size, 0);

	if (result) {
		debug("[-] Failed to send dataxfer packet");
		goto fail;
	} else {
		if (do_hexdump) {
			hexdump_log_base(recv_buf, buf_size, (unsigned int) strtol(start_addr, NULL, 16));
		}

		fd = open("dump.bin", O_CREAT | O_WRONLY, S_IRUSR | S_IWUSR);
		
		if (fd == -1) {
			debug("[-] Failed to open dump.bin, errno %d", errno);
			goto fail;
		}

		write(fd, recv_buf, buf_size);
	}

	ret = 0;

fail:
	free(recv_buf);
	return ret;


}


int initialise_device(struct device_data* dev_data) {
	struct libusb_device **devs;
	struct libusb_context *ctx = NULL;
	struct libusb_device *samsung_device = NULL;
	struct libusb_device_handle *device_handle;
	struct libusb_device_descriptor device_descriptor;
	struct libusb_config_descriptor *config_descriptor;
	const struct libusb_endpoint_descriptor *endpoint;
	unsigned char string_buffer[128];
	bool detached_driver = false, interface_claimed = false;
	int r, result, interface_index, alt_setting_index, in_endpoint, out_endpoint, in_endpoint_address, out_endpoint_address;
	int curr_interface, curr_setting, curr_endp;
	ssize_t cnt, current;
	r = libusb_init(&ctx);
	
	if (r < 0) {
		debug("[*] Init Error");
		return 1;
	}

	libusb_set_debug(ctx, 3);
	cnt = libusb_get_device_list(ctx, &devs);
	if (cnt < 0) {
		debug("[*] Get Device Error");
	}
	debug("[*] %zu Devices in list.", cnt);
	
	for (current = 0; current < cnt; current++) {
		debug("[*]  *** Device %zu *** \n", current);
		if (grepdev(devs[current]) == 1) {
			debug("[*] Found target device");
			samsung_device = devs[current];
			libusb_ref_device(samsung_device);
			break;
		}
	}
	
	libusb_free_device_list(devs, cnt);

	if (!samsung_device) {
		debug("[*] Target device not found");
		libusb_exit(ctx);
		return 0;
	}

	result = libusb_open(samsung_device, &device_handle);
	if (result != LIBUSB_SUCCESS)
	{
		debug("[-] Failed to access device. libusb error: %d", result);
		return 0;
	}

	result = libusb_get_device_descriptor(samsung_device, &device_descriptor);
	if (result != LIBUSB_SUCCESS)
	{
		debug("[-] Failed to retrieve device description");
		return 0;
	}


	if (libusb_get_string_descriptor_ascii(device_handle, device_descriptor.iManufacturer,
		string_buffer, 128) >= 0)
	{
		debug("[*]       Manufacturer: \"%s\"", string_buffer);
	}

	if (libusb_get_string_descriptor_ascii(device_handle, device_descriptor.iProduct,
		string_buffer, 128) >= 0)
	{
		debug("[*]            Product: \"%s\"", string_buffer);
	}

	if (libusb_get_string_descriptor_ascii(device_handle, device_descriptor.iSerialNumber,
		string_buffer, 128) >= 0)
	{
		debug("[*]          Serial No: \"%s\"", string_buffer);
	}

	debug("[*]             length: %d", device_descriptor.bLength);
	debug("[*]       device class: %d", device_descriptor.bDeviceClass);
	debug("[*]                S/N: %d", device_descriptor.iSerialNumber);
	debug("[*]            VID:PID: %04X:%04X", device_descriptor.idVendor, device_descriptor.idProduct);
	debug("[*]          bcdDevice: %04X", device_descriptor.bcdDevice);
	debug("[*]    iMan:iProd:iSer: %d:%d:%d", device_descriptor.iManufacturer, device_descriptor.iProduct,
		device_descriptor.iSerialNumber);
	debug("[*]           nb confs: %d", device_descriptor.bNumConfigurations);

	result = libusb_get_config_descriptor(samsung_device, 0, &config_descriptor);

	if (result != LIBUSB_SUCCESS || !config_descriptor)
	{
		debug("[-] Failed to retrieve config descriptor");
		return 0;
	}

	interface_index = -1;
	alt_setting_index = -1;

	for (curr_interface = 0; curr_interface < config_descriptor->bNumInterfaces; curr_interface++) {
		for (curr_setting = 0 ; curr_setting < config_descriptor->interface[curr_interface].num_altsetting; curr_setting++) {
			debug("[*] interface[%d].altsetting[%d]: num endpoints = %d",
				curr_interface, curr_setting, config_descriptor->interface[curr_interface].altsetting[curr_setting].bNumEndpoints);
			debug("[*]    Class.SubClass.Protocol: %02X.%02X.%02X",
				config_descriptor->interface[curr_interface].altsetting[curr_setting].bInterfaceClass,
				config_descriptor->interface[curr_interface].altsetting[curr_setting].bInterfaceSubClass,
				config_descriptor->interface[curr_interface].altsetting[curr_setting].bInterfaceProtocol);
		
			in_endpoint_address = -1;
			out_endpoint_address = -1;

			for (curr_endp = 0; curr_endp < config_descriptor->interface[curr_interface].altsetting[curr_setting].bNumEndpoints; curr_endp++) {
				endpoint = &config_descriptor->interface[curr_interface].altsetting[curr_setting].endpoint[curr_endp];
					debug("[*]        endpoint[%d].address: %02X", curr_endp, endpoint->bEndpointAddress);
					debug("[*]            max packet size: %04X", endpoint->wMaxPacketSize);
					debug("[*]           polling interval: %02X", endpoint->bInterval);

				if (endpoint->bEndpointAddress & LIBUSB_ENDPOINT_IN) {
					in_endpoint_address = endpoint->bEndpointAddress;
					debug("[*] Assigned in_endpoint_address = %d", in_endpoint_address);
				}
				else {
					out_endpoint_address = endpoint->bEndpointAddress;
					debug("[*] Assigned out_endpoint_address = %d", out_endpoint_address);

				}
			}

			if (interface_index < 0
				&& config_descriptor->interface[curr_interface].altsetting[curr_setting].bNumEndpoints == 2
				&& config_descriptor->interface[curr_interface].altsetting[curr_setting].bInterfaceClass == USB_CLASS_CDC_DATA
				&& in_endpoint_address != -1
				&& out_endpoint_address != -1)
			{
				interface_index = curr_interface;
				alt_setting_index = curr_setting;
				in_endpoint = in_endpoint_address;
				out_endpoint = out_endpoint_address;

				debug("[*] Got match for device. interface_index = %d, alt_setting_index = %d, in_endpoint = %d, out_endpoint = %d", interface_index, alt_setting_index, in_endpoint, out_endpoint);
			}
		}
	}

	libusb_free_config_descriptor(config_descriptor);

	if (interface_index < 0)
	{
		debug("[-] Failed to find correct interface configuration");
		return 0;
	}

	debug("[*] Claiming interface...");

	result = libusb_claim_interface(device_handle, interface_index);

	if (result != LIBUSB_SUCCESS)
	{
		detached_driver = true;
		debug("[*] Attempt failed. Detaching driver...");
		libusb_detach_kernel_driver(device_handle, interface_index);
		debug("[*] Claiming interface again...");
		result = libusb_claim_interface(device_handle, interface_index);
	}

	if (result != LIBUSB_SUCCESS)
	{
		debug("[*] Claiming interface failed!");
		return 0;
	}

	interface_claimed = true;
	debug("[*] Interface claimed");

	debug("[*] Setting up interface...");

	result = libusb_set_interface_alt_setting(device_handle, interface_index, alt_setting_index);

	if (result != LIBUSB_SUCCESS)
	{
		debug("[*] Setting up interface failed!");
		return 0;
	}

	debug("[*] Setting up interface succeeded");

	dev_data->samsung_device = samsung_device;
	dev_data->device_handle = device_handle;
	dev_data->interface_index = interface_index;
	dev_data->alt_setting_index = alt_setting_index;
	dev_data->in_endpoint = in_endpoint;
	dev_data->out_endpoint = out_endpoint;

	return 1;

}

int grepdev(libusb_device *dev) {
	struct libusb_device_descriptor desc;
	struct libusb_config_descriptor *config;
	const struct libusb_interface *inter;
	const struct libusb_interface_descriptor *interdesc;
	const struct libusb_endpoint_descriptor *epdesc;
	uint8_t i, k;
	int j, found = 0;
	
	int r = libusb_get_device_descriptor(dev, &desc);
	
	if (r < 0) {
		debug("[-] failed to get device descriptor");
		return 0;
	}

	debug("[*] Number of possible configurations: %d", desc.bNumConfigurations);
	debug("[*] Device Class: %d", desc.bDeviceClass);
	debug("[*] Vendor ID: %04x", desc.idVendor);
	debug("[*] Product ID: %04x", desc.idProduct);

	if (desc.idVendor == ID_SAMSUNG && desc.idProduct == ID_GALAXY) {
		found = 1;
	}

	libusb_get_config_descriptor(dev, 0, &config);

	debug("[*] Number of Interfaces: %hd\n", config->bNumInterfaces);
	for (i = 0; i < config->bNumInterfaces; i++) {
		debug("[*] ---- Interface number %hd --- ", i);
		inter = &config->interface[i];
		debug("[*] Number of alternate settings: %d\n", inter->num_altsetting);
		for (j = 0; j < inter->num_altsetting; j++) {
			debug("[*]  --> Alternate setting %d", j);
			interdesc = &inter->altsetting[j];
			debug("[*] Altsetting Interface Number: %d", interdesc->bInterfaceNumber);
			debug("[*] Number of endpoints: %d", interdesc->bNumEndpoints);
			for (k = 0; k < interdesc->bNumEndpoints; k++) {
				debug("[*]  -> Endpoint %d", k);
				epdesc = &interdesc->endpoint[k];
				debug("[*] Descriptor Type: %d", epdesc->bDescriptorType);
				debug("[*] Attributes: %08x", epdesc->bmAttributes);
				debug("[*] Max packet size: %04x", epdesc->wMaxPacketSize);
				debug("[*] EP Address: %d", epdesc->bEndpointAddress);
			}
		}
	}

	debug("[*] \n");
	libusb_free_config_descriptor(config);
	return found;
}


int main(int argc, char** argv) {
	struct device_data dev_data;
	bool do_hexdump = false;
	int result;

	if (argc < 3) {
		printf("[-] Usage: sboot_dump start_addr end_addr (in hex, no leading 0x) <print>\n");
		return -1;
	}

	result = initialise_device(&dev_data);

	if (result == 0) {
		debug("[-] Failed initialise_device()");
		return 0;
	}

	if (argc > 3) {
		do_hexdump = !(strcmp(argv[3], "print"));
	}

	do_upload(&dev_data, argv[1], argv[2], do_hexdump);

}
