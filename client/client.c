#include <Windows.h>
#include <stdio.h>
#include "..\physmem_sys\PhysmemCommon.h"

void hexdump(unsigned char* data, size_t size) {
	char ascii[17] = { 0 };
	size_t i;

	for (i = 0; i < size; ++i) {
		unsigned char c = data[i];
		size_t next = i + 1;
		printf("%02X ", c);
		ascii[i % 16] = isprint(c) ? c : '.';
		if (next % 8 == 0 || next == size) {
			printf(" ");
			if (next % 16 == 0) {
				printf("|  %s \n", ascii);
			}
			else if (next == size) {
				size_t j;
				ascii[size % 16] = '\0';
				if (size % 16 <= 8) {
					printf(" ");
				}
				for (j = size % 16; j < 16; ++j) {
					printf("   ");
				}
				printf("|  %s \n", ascii);
			}
		}
		fflush(stdout);
	}
}

int main(int argc, char* argv[]) {
	
	if (argc != 3) {
		printf("Usage: %s <physaddr> <size>\n", argv[0]);
		return 0;
	}

	HANDLE hDevice = CreateFile(L"\\\\.\\Physmem", GENERIC_WRITE, 
		FILE_SHARE_WRITE, NULL, OPEN_EXISTING, 0, NULL);

	if (hDevice == INVALID_HANDLE_VALUE) {
		perror("CreateFile()");
		return STATUS_INVALID_HANDLE;
	}

	PHYSMEM_REQUEST PhysmemRequest;
	DWORD returned = 0;
	void* virtaddr = 0;

	PhysmemRequest.PhysicalAddress = strtoull(argv[1], NULL, 0);
	PhysmemRequest.Size = strtoull(argv[2], NULL, 0);

	BOOL success = DeviceIoControl(hDevice,
		IOCTL_PHYSMEM_GET_OBJECT_HANDLE,
		&PhysmemRequest, sizeof(PHYSMEM_REQUEST),
		&virtaddr, sizeof(UINT64),
		&returned, NULL);

	if (!success) {
		printf("DeviceIoControl() error: 0x%x\n", GetLastError());
		goto done;
	}

	printf("Received VirtAddr: 0x%p\n", virtaddr);
	printf("Size: 0x%llx\n", PhysmemRequest.Size);
	hexdump((unsigned char*)virtaddr, PhysmemRequest.Size);

	done:
	CloseHandle(hDevice);
}
