To compile: gcc -o sboot_dump sboot_dump.c `pkg-config libusb-1.0 --libs --cflags`

Note: The code currently has a bug that only lets you pull 1024 bytes at a time. To get bigger dumps just run this in a loop, or wait until I get time to fix it

