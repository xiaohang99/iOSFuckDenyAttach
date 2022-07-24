
// find_kernel_base_under_checkra1n.h
#ifndef FIND_KERNEL_BASE_UNDER_CHECKRA1N
#define FIND_KERNEL_BASE_UNDER_CHECKRA1N 1
#include <mach/mach.h>
#include <assert.h>
#include <stdbool.h>
#include <stdio.h>

void kernel_task_init();
uint64_t kernel_base_init();
bool kernel_read(uint64_t address, void *data, size_t size);
uint64_t kernel_read64(uint64_t address);
bool kernel_write(uint64_t address, const void *data, size_t size);

#define KERNEL_WRITE64(addr , val) kernel_write(addr, &val, sizeof(int64_t));

#define KERNEL_WRITE32(addr , val) kernel_write(addr, &val, sizeof(int32_t));


#endif