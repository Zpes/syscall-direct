#include <windows.h>
#include "syscall_direct.h"

auto main() -> int
{
	void* alloc = 0; SIZE_T size = 4096;

	NTSTATUS status = syscall_direct::create_syscall<NTSTATUS>("ZwAllocateVirtualMemory", GetCurrentProcess(), (PVOID*)&alloc, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

	printf_s("[syscall-direct] status -> %p\n", status);
	printf_s("[syscall-direct] allocation -> %p\n", alloc);

	while (1);
}