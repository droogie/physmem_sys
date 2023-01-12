#include <ntifs.h>
#include "PhysmemCommon.h"

UNICODE_STRING DEVICE_NAME = RTL_CONSTANT_STRING(L"\\Device\\Physmem");
UNICODE_STRING SYMLINK = RTL_CONSTANT_STRING(L"\\??\\Physmem");

NTSTATUS MapPhysicalMemory(PUINT_PTR VirtualAddress, UINT_PTR PhysicalAddress, SIZE_T Size) {
	NTSTATUS status = STATUS_SUCCESS;
	UNICODE_STRING DeviceName;
	OBJECT_ATTRIBUTES ObjectAttributes;
	HANDLE hSection = NULL;
	PHYSICAL_ADDRESS ViewBase;
	PUCHAR pBaseAddress = NULL;

	if (PhysicalAddress & 0xfff) {
		status = STATUS_INVALID_PARAMETER;
		goto error;
	}

	if ((PhysicalAddress + Size) < PhysicalAddress) {
		status = STATUS_INTEGER_OVERFLOW;
		goto error;
	}

	if (SIZE_PAGE_ALIGN(Size) < Size) {
		status = STATUS_INTEGER_OVERFLOW;
		goto error;
	}

	Size = SIZE_PAGE_ALIGN(Size);

	RtlInitUnicodeString(&DeviceName, L"\\Device\\PhysicalMemory");

	InitializeObjectAttributes(&ObjectAttributes,
		&DeviceName,
		OBJ_CASE_INSENSITIVE,
		(HANDLE)NULL,
		(PSECURITY_DESCRIPTOR)NULL);

	status = ZwOpenSection(
		&hSection,
		SECTION_ALL_ACCESS, 
		&ObjectAttributes);

	if (!NT_SUCCESS(status))
	{
		goto error;
	}

	ViewBase.QuadPart = PhysicalAddress;

	status = ZwMapViewOfSection(
		hSection,
		NtCurrentProcess(),
		(PVOID *)&pBaseAddress,
		0L,
		Size,
		&ViewBase,
		&Size,
		ViewShare,
		0,
		PAGE_READWRITE | PAGE_NOCACHE);

	if (!NT_SUCCESS(status))
	{
		goto error;
	}
	
	*VirtualAddress = (UINT64)pBaseAddress;

done:
	if (hSection) {
		ZwClose(hSection);
	}

	return status;

error:
	*VirtualAddress = 0;
	goto done;
}

NTSTATUS IoPortAccess(UINT16 Port, UINT8 Op, PUINT32 Buffer) {
	NTSTATUS status = STATUS_SUCCESS;
	switch (Op) {
		case CMD_IO_READ_BYTE:
			*((UCHAR *)Buffer) = __inbyte(Port);
			break;

		case CMD_IO_READ_WORD:
			*((UINT16 *)Buffer) = __inword(Port);
			break;

		case CMD_IO_READ_DWORD:
			*Buffer = __indword(Port);
			break;

		case CMD_IO_WRITE_BYTE:
			__outbyte(Port, *((UCHAR *)Buffer));
			break;

		case CMD_IO_WRITE_WORD:
			__outword(Port, *((UINT16 *)Buffer));
			break;

		case CMD_IO_WRITE_DWORD:
			__outdword(Port, *Buffer);
			break;

		default:
			status = STATUS_INVALID_PARAMETER;
			break;
	}

	return status;
}

void PhysmemUnload(PDRIVER_OBJECT DriverObject) {

	IoDeleteSymbolicLink(&SYMLINK);
	IoDeleteDevice(DriverObject->DeviceObject);
}

NTSTATUS PhysmemCreateClose(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
	return STATUS_SUCCESS;
}

NTSTATUS PhysmemDeviceControl(PDEVICE_OBJECT DeviceObject, PIRP Irp) {
	UNREFERENCED_PARAMETER(DeviceObject);
	
	IO_STACK_LOCATION* stack = IoGetCurrentIrpStackLocation(Irp);
	NTSTATUS status = STATUS_INVALID_DEVICE_REQUEST;
	ULONG len;
	PPHYSMEM_REQUEST PhysmemRequest;
	PIO_PORT_REQUEST IoPortRequest;

	switch (stack->Parameters.DeviceIoControl.IoControlCode) {
		case IOCTL_PHYSMEM_GET_OBJECT_HANDLE:
			len = stack->Parameters.DeviceIoControl.InputBufferLength;

			if (len < sizeof(PHYSMEM_REQUEST)) {
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			else if (len > sizeof(PHYSMEM_REQUEST)) {
				status = STATUS_BUFFER_OVERFLOW;
				break;
			}

			PhysmemRequest = (PPHYSMEM_REQUEST)Irp->AssociatedIrp.SystemBuffer;

			if (PhysmemRequest == NULL) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			if (!PhysmemRequest->Size) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			status = MapPhysicalMemory((UINT_PTR*)Irp->AssociatedIrp.SystemBuffer, 
				PhysmemRequest->PhysicalAddress, 
				PhysmemRequest->Size);

			Irp->IoStatus.Information = sizeof(UINT_PTR);

			break;

		case IOCTL_PHYSMEM_ACCESS_IO_PORT:
			len = stack->Parameters.DeviceIoControl.InputBufferLength;

			if (len < sizeof(IO_PORT_REQUEST)) {
				status = STATUS_BUFFER_TOO_SMALL;
				break;
			}
			else if (len > sizeof(IO_PORT_REQUEST)) {
				status = STATUS_BUFFER_OVERFLOW;
				break;
			}

			IoPortRequest = (PIO_PORT_REQUEST)Irp->AssociatedIrp.SystemBuffer;

			if (IoPortRequest == NULL) {
				status = STATUS_INVALID_PARAMETER;
				break;
			}

			status = IoPortAccess(IoPortRequest->Port, IoPortRequest->Op, &(IoPortRequest->Data));
			Irp->IoStatus.Information = sizeof(IO_PORT_REQUEST);

			break;

		default:
			status = STATUS_INVALID_DEVICE_REQUEST;
			Irp->IoStatus.Information = 0;
			break;
	}

	Irp->IoStatus.Status = status;

	IoCompleteRequest(Irp, IO_NO_INCREMENT);

	return status;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT DriverObject, PUNICODE_STRING RegistryPath) {
	NTSTATUS status;
	UNREFERENCED_PARAMETER(RegistryPath);

	PDEVICE_OBJECT DeviceObject;
	status = IoCreateDevice(
		DriverObject,
		0,
		&DEVICE_NAME,
		FILE_DEVICE_UNKNOWN,
		0,
		FALSE,
		&DeviceObject
	);

	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create device object (0x%08X)\n", status);
		return status;
	}

	DriverObject->Flags |= DO_DIRECT_IO;

	DriverObject->DriverUnload = PhysmemUnload;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = PhysmemCreateClose;
	DriverObject->MajorFunction[IRP_MJ_CREATE] = PhysmemCreateClose;
	DriverObject->MajorFunction[IRP_MJ_DEVICE_CONTROL] = PhysmemDeviceControl;

	status = IoCreateSymbolicLink(&SYMLINK, &DEVICE_NAME);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed to create symbolic link (0x%08X)\n", status);
		IoDeleteDevice(DeviceObject);
		return status;
	}

	return status;
}