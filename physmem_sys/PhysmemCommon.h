#pragma once

#define CTL_CODE(DeviceType, Function, Method, Access) ( \
    ((DeviceType) << 16) | ((Access) << 14) | ((Function) << 2) | (Method) )

#define PHYSMEM_DEVICE 0x8000

#define IOCTL_PHYSMEM_GET_OBJECT_HANDLE CTL_CODE(PHYSMEM_DEVICE, \
    0x800, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define IOCTL_PHYSMEM_ACCESS_IO_PORT CTL_CODE(PHYSMEM_DEVICE, \
    0x801, METHOD_BUFFERED, FILE_ANY_ACCESS)

#define SIZE_PAGE_MASK (~(PAGE_SIZE-1))
#define SIZE_PAGE_ALIGN(x) ((x + PAGE_SIZE - 1) & SIZE_PAGE_MASK)

#define CMD_IO_READ_BYTE   0
#define CMD_IO_READ_WORD   1
#define CMD_IO_READ_DWORD  2
#define CMD_IO_WRITE_BYTE  3
#define CMD_IO_WRITE_WORD  4
#define CMD_IO_WRITE_DWORD 5

typedef struct _PHYSMEM_REQUEST
{
	UINT64    PhysicalAddress;
	SIZE_T    Size;
} PHYSMEM_REQUEST, *PPHYSMEM_REQUEST;

typedef struct _IO_PORT_REQUEST
{
    UINT8    Op;
    UINT16   Port;
    UINT32   Data;
} IO_PORT_REQUEST, *PIO_PORT_REQUEST;