# physmem_sys

An unrestricted driver to map physical memory to userland. It exposes an IOCTL for requesting a physical address and length, which will return a virtual address to leverage in userland.

## Build

Included is the Visual Studio 2019 project with a solution containing both the `physmem_sys` driver and a simple `client` utility showcasing the IOCTL usage.

## Loading/Unloading

You can trivially load/unload the driver leveraging the [OSR](https://www.osronline.com/) Driver Loader utility.

## Usage

The `IOCTL` expects that the physical address provided is page aligned. The included `client` project will perform a `hexdump()` of a page_aligned physical address and length.