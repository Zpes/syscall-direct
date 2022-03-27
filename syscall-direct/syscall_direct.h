#pragma once
#include <windows.h>
#include <iostream>

#include "undocumented.h"

unsigned char syscall_shellcode[]
{
	0x4C, 0x8B, 0xD1,			  // mov r10,rcx
	0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, syscall_index
	0x0F, 0x05,					  // syscall
	0xC3					      // ret
};

enum syscall_numbers
{
	ZwAllocateVirtualMemory = 0x18,
	ZwAllocateVirtualMemoryEx = 0x76,
	ZwAllocateUuids = 0x75,
	ZwClose = 0xf,
	ZwContinue = 0x43,
	ZwCreateFile = 0x55,
	ZwMapViewOfSection = 0x28,
	ZwOpenFile = 0x33,
	ZwQueryInformationProcess = 0x19,
	ZwQueryInformationThread = 0x25,
	ZwFreeVirtualMemory = 0x1e,
	ZwProtectVirtualMemory = 0x50,
	NtAddDriverEntry = 0x6b,
};

namespace syscall_direct
{
	static void* shellcode_allocation = 0;
	static uintptr_t module_base = 0;

	namespace helpers
	{
		inline uintptr_t get_module_base(std::string module_name)
		{
			PPEB64 peb = (PPEB64)__readgsqword(0x60);

			PPEB_LDR_DATA ldr_data = (PPEB_LDR_DATA)peb->Ldr;

			for (PLIST_ENTRY list_entry = ldr_data->InLoadOrderModuleList.Flink; list_entry != &ldr_data->InLoadOrderModuleList; list_entry = list_entry->Flink)
			{
				PLDR_DATA_TABLE_ENTRY ldr_entry = CONTAINING_RECORD(list_entry, LDR_DATA_TABLE_ENTRY, InLoadOrderLinks);

				if (ldr_entry)
				{
					wchar_t wtext[20];
					mbstowcs(wtext, module_name.c_str(), module_name.length());
					LPWSTR module_name_ws = wtext;

					if (wcscmp(module_name_ws, ldr_entry->BaseDllName.Buffer) == 0)
					{
						return (uintptr_t)ldr_entry->DllBase;
					}
				}
			}

			return 0;
		}

		inline uintptr_t get_export_address(uintptr_t module_base, const char* export_name)
		{
			PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)module_base;

			if (dos->e_magic == IMAGE_DOS_SIGNATURE)
			{
				PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((uintptr_t)dos + (uintptr_t)dos->e_lfanew);

				if (nt->Signature == IMAGE_NT_SIGNATURE)
				{
					uintptr_t export_directory_va = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
					PIMAGE_EXPORT_DIRECTORY export_directory = (PIMAGE_EXPORT_DIRECTORY)((uintptr_t)module_base + (uintptr_t)export_directory_va);

					if (export_directory)
					{
						DWORD* name_offset_array = (DWORD*)(module_base + export_directory->AddressOfNames);
						WORD* ordinal_array = (WORD*)(module_base + export_directory->AddressOfNameOrdinals);
						DWORD* function_offset_array = (DWORD*)(module_base + export_directory->AddressOfFunctions);

						for (size_t i = 0; i < export_directory->NumberOfNames; i++)
						{
							const char* current_name = reinterpret_cast<const char*>((uintptr_t)module_base + name_offset_array[i]);

							if (strcmp(current_name, export_name) == 0)
							{
								return (uintptr_t(module_base) + DWORD(function_offset_array[ordinal_array[i]]));
							}
						}
					}
				}
			}

			return 0;
		}
	}

	template <typename T, typename ...args> T create_syscall_by_syscall_number(int syscall_number, args... arguments)
	{
		if (!syscall_direct::shellcode_allocation)
			syscall_direct::shellcode_allocation = VirtualAlloc(nullptr, sizeof(syscall_shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);

		if (syscall_direct::shellcode_allocation != nullptr)
		{
			memcpy(&syscall_shellcode[4], &syscall_number, sizeof(int));
			memcpy(syscall_direct::shellcode_allocation, &syscall_shellcode, sizeof(syscall_shellcode));

			T(__stdcall * func)(args...);
			*(void**)&func = syscall_direct::shellcode_allocation;

			return func(arguments...);
		}

		return 0;
	}

	template <typename T, typename ...args> T create_syscall(LPCSTR syscall_name, args... arguments)
	{
		if (!syscall_direct::module_base)
			syscall_direct::module_base = syscall_direct::helpers::get_module_base("ntdll.dll");

		if (syscall_direct::module_base)
		{
			uintptr_t export_address = syscall_direct::helpers::get_export_address(syscall_direct::module_base, syscall_name);

			if (export_address != 0)
			{
				int syscall_number = *(int*)(export_address + 0x4);

				return syscall_direct::create_syscall_by_syscall_number<T>(syscall_number, arguments...);
			}
		}

		return 0;
	}
}
