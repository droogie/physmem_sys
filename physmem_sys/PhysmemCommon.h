#pragma once

#define CTL_CODE(DeviceType, Function, Method, Access) ( \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) )

#define PHYSMEM_DEVICE 0x8000

#define IOCTL_PHYSMEM_GET_OBJECT_HANDLE CTL_CODE(PHYSMEM_DEVICE, \
    0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define SIZE_PAGE_MASK (~(PAGE_SIZE-1))
#define SIZE_PAGE_ALIGN(x) ((x + PAGE_SIZE - 1) & SIZE_PAGE_MASK)

typedef struct _PHYSMEM_REQUEST
{
	UINT64    PhysicalAddress;
	SIZE_T    Size;
} PHYSMEM_REQUEST, *PPHYSMEM_REQUEST;