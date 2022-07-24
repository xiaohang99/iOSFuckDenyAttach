// find_kernel_base_under_checkra1n.c

#include "find_kernel_base_under_checkra1n.h"

// ---- mach_vm.h ---------------------------------------------------------------------------------

extern
kern_return_t mach_vm_read_overwrite
(
	vm_map_t target_task,
	mach_vm_address_t address,
	mach_vm_size_t size,
	mach_vm_address_t data,
	mach_vm_size_t *outsize
);

extern
kern_return_t mach_vm_region_recurse
(
	vm_map_t target_task,
	mach_vm_address_t *address,
	mach_vm_size_t *size,
	natural_t *nesting_depth,
	vm_region_recurse_info_t info,
	mach_msg_type_number_t *infoCnt
);

kern_return_t mach_vm_write
(
    vm_map_t target_task, 
    mach_vm_address_t address, 
    vm_offset_t data, 
    mach_msg_type_number_t dataCnt
);

// ---- Kernel task -------------------------------------------------------------------------------

static mach_port_t kernel_task_port;

void
kernel_task_init() {
	task_for_pid(mach_task_self(), 0, &kernel_task_port);
	assert(kernel_task_port != MACH_PORT_NULL);
	printf("kernel task: 0x%x\n", kernel_task_port);
}

bool
kernel_read(uint64_t address, void *data, size_t size) {
	mach_vm_size_t size_out;
	kern_return_t kr = mach_vm_read_overwrite(kernel_task_port, address, size,
			(mach_vm_address_t) data, &size_out);
	return (kr == KERN_SUCCESS);
}

uint64_t
kernel_read64(uint64_t address) {
	uint64_t value = 0;
	bool ok = kernel_read(address, &value, sizeof(value));
	if (!ok) {
		printf("error: %s(0x%016llx)\n", __func__, address);
	}
	return value;
}


bool kernel_write(uint64_t address, const void *data, size_t size) {
    size_t offset = 0;
    kern_return_t kr = KERN_FAILURE;
    while (offset < size) {
        size_t chunk = 2048;
        if (chunk > size - offset) {
            chunk = size - offset;
        }
        kr = mach_vm_write(kernel_task_port, address + offset, (mach_vm_offset_t)data + offset, (int)chunk);
        if (kr != KERN_SUCCESS) {
            printf("error: %s(0x%016llx)\n",__func__, address);
            break;
        }
        offset += chunk;
    }
    return (kr == KERN_SUCCESS);
}


// ---- Kernel base -------------------------------------------------------------------------------

static uint64_t kernel_base;

bool
is_kernel_base(uint64_t base) {
	uint64_t header[2] = { 0x0100000cfeedfacf, 0x0000000200000000 };
	uint64_t data[2] = {};
	bool ok = kernel_read(base, &data, sizeof(data));
	if (ok && memcmp(data, header, sizeof(data)) == 0) {
		return true;
	}
	return false;
}

bool
kernel_base_init_with_unsafe_heap_scan() {
	uint64_t kernel_region_base = 0xfffffff000000000;
	uint64_t kernel_region_end  = 0xfffffffbffffc000;
	// Try and find a pointer in the kernel heap to data in the kernel image. We'll take the
	// smallest such pointer.
	uint64_t kernel_ptr = (uint64_t)(-1);
	mach_vm_address_t address = 0;
	for (;;) {
		// Get the next memory region.
		mach_vm_size_t size = 0;
		uint32_t depth = 2;
		struct vm_region_submap_info_64 info;
		mach_msg_type_number_t count = VM_REGION_SUBMAP_INFO_COUNT_64;
		kern_return_t kr = mach_vm_region_recurse(kernel_task_port, &address, &size,
				&depth, (vm_region_recurse_info_t) &info, &count);
		if (kr != KERN_SUCCESS) {
			break;
		}
		// Skip any region that is not on the heap, not in a submap, not readable and
		// writable, or not fully mapped.
		int prot = VM_PROT_READ | VM_PROT_WRITE;
		if (info.user_tag != 12
		    || depth != 1
		    || (info.protection & prot) != prot
		    || info.pages_resident * 0x4000 != size) {
			goto next;
		}
		// Read the first word of each page in this region.
		for (size_t offset = 0; offset < size; offset += 0x4000) {
			uint64_t value = 0;
			bool ok = kernel_read(address + offset, &value, sizeof(value));
			if (ok
			    && kernel_region_base <= value
			    && value < kernel_region_end
			    && value < kernel_ptr) {
				kernel_ptr = value;
			}
		}
next:
		address += size;
	}
	// If we didn't find any such pointer, abort.
	if (kernel_ptr == (uint64_t)(-1)) {
		return false;
	}
	printf("found kernel pointer %p\n", (void *)kernel_ptr);
	// Now that we have a pointer, we want to scan pages until we reach the kernel's Mach-O
	// header.
	uint64_t page = kernel_ptr & ~0x3fff;
	for (;;) {
		bool found = is_kernel_base(page);
		if (found) {
			kernel_base = page;
			return true;
		}
		page -= 0x4000;
	}
	return false;
}

uint64_t
kernel_base_init() {
	bool ok = kernel_base_init_with_unsafe_heap_scan();
	assert(ok);
	printf("kernel base: %p\n", (void *)kernel_base);
    return kernel_base;
}
