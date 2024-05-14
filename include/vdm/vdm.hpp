#pragma once
#include <windows.h>
#include <string_view>
#include <vector>
#include <thread>
#include <atomic>
#include <mutex>
#include <functional>
#include "util.hpp"


namespace vdm {




    using myNtAllocateVirutalMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, PVOID* BaseAddress, ULONG_PTR ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect);

    using myNtWriteVirtualMemory = NTSTATUS(NTAPI*)(HANDLE ProcessHandle, LPVOID BaseAddress, char* Buffer, ULONG RegionSize, PULONG numBytesWritten);

    using myNtCreateThreadEx = NTSTATUS(NTAPI*)(PHANDLE hThread, ACCESS_MASK DesiredAccess, PVOID ObjectAttributes, HANDLE ProcessHandle, PVOID lpStartAddress, PVOID lpParameter, ULONG Flags, SIZE_T ZeroBits, SIZE_T SizeOfStackCommit, SIZE_T SizeOfStackReserve, PVOID lpBytesBuffer);




    // change this to whatever you want :^)
    constexpr std::pair<const char*, const char*> syscall_hook = { "NtShutdownSystem", "ntdll.dll" };
    inline std::atomic<bool> is_page_found = false;
    inline std::atomic<void*> syscall_address = nullptr;
    inline std::uint16_t nt_page_offset;
    inline std::uint32_t nt_rva;
    inline std::uint8_t* ntoskrnl;

    using read_phys_t = std::function<bool(void*, void*, std::size_t)>;
    using write_phys_t = std::function<bool(void*, void*, std::size_t)>;

    class vdm_ctx {
    public:
        vdm_ctx() = default;
        vdm_ctx(read_phys_t& read_func, write_phys_t& write_func);
        void set_read(read_phys_t& read_func);
        void set_write(write_phys_t& write_func);
        void rkm(void* dst, void* src, std::size_t size);
        void wkm(void* dst, void* src, std::size_t size);
       // void syscall_MMAllocateVirtualMemory(std::uint32_t pid, PVOID* BaseAddress, ULONG_PTR ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect);
        


        template <class T, class ... Ts>
        __forceinline std::invoke_result_t<T, Ts...> syscall(void* addr, Ts ... args) const {
            static const auto proc = GetProcAddress(LoadLibraryA(syscall_hook.second), syscall_hook.first);

            static std::mutex syscall_mutex;
            syscall_mutex.lock();

            // jmp [rip+0x0]
            std::uint8_t jmp_code[] = {
                    0xff, 0x25, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00
            };

            std::uint8_t orig_bytes[sizeof jmp_code];
            *reinterpret_cast<void**>(jmp_code + 6) = addr;
            read_phys(vdm::syscall_address.load(), orig_bytes, sizeof orig_bytes);

            // execute hook...
            write_phys(vdm::syscall_address.load(), jmp_code, sizeof jmp_code);
            auto result = reinterpret_cast<T>(proc)(args ...);
            write_phys(vdm::syscall_address.load(), orig_bytes, sizeof orig_bytes);

            syscall_mutex.unlock();
            return result;
        }

        __forceinline auto get_peprocess(std::uint32_t pid) -> PEPROCESS {
            static const auto ps_lookup_peproc = util::get_kmodule_export("ntoskrnl.exe", "PsLookupProcessByProcessId");

            PEPROCESS peproc = nullptr;
            this->syscall<PsLookupProcessByProcessId>(ps_lookup_peproc, (HANDLE)pid, &peproc);
            return peproc;
        }
        
     //   __forceinline auto MMvirtalloc()
        //BEGIN TESTING
      
      __forceinline auto syscall_NtAllocateVirtualMemory(std::uint32_t pid, PVOID* BaseAddress, ULONG_PTR ZeroBits, PULONG RegionSize, ULONG AllocationType, ULONG Protect) {
            static const auto ptr_myNtAllocateVirutalMemory = util::get_kmodule_export("ntoskrnl.exe", "NtAllocateVirtualMemory");
            this->syscall<myNtAllocateVirutalMemory>(ptr_myNtAllocateVirutalMemory, (HANDLE)pid, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect);

              }

     //  inline void syscall_VirtualAllocEx(std::uint32_t pid, LPVOID BaseAddress, SIZE_T RegionSize, ULONG AllocationType, ULONG Protect) {

     //       static const auto ptr_VirtualAllocEx = util::get_kmodule_export("ntoskrnl.exe", "VirtualAllocEx");
     //       this->syscall<decltype(&VirtualAllocEx)>(ptr_VirtualAllocEx, (HANDLE)pid, BaseAddress, RegionSize, AllocationType, Protect);

     //   }

     //inline void syscall_VirtualFreeEx(std::uint32_t pid, LPVOID BaseAddress, SIZE_T RegionSize, DWORD dwFreeType) {

     //       static const auto ptr_VirtualAllocEx = util::get_kmodule_export("ntoskrnl.exe", "VirtualFreeEx");
     //       this->syscall<decltype(&VirtualFreeEx)>(ptr_VirtualAllocEx, (HANDLE)pid, BaseAddress, RegionSize, dwFreeType);
     //   }


     // inline void syscall_VirtualProtectEx(std::uint32_t pid, LPVOID BaseAddress, SIZE_T RegionSize, DWORD NewProtect, PDWORD oldProtect) {

     //       static const auto ptr_VirtualAllocEx = util::get_kmodule_export("ntoskrnl.exe", "VirtualProtectEx");
     //       this->syscall<decltype(&VirtualProtectEx)>(ptr_VirtualAllocEx, (HANDLE)pid, BaseAddress, RegionSize, NewProtect, oldProtect);
     //   }



        //END TESTING

       
        __forceinline auto get_peb(std::uint32_t pid) -> PPEB {
            static const auto get_peb = util::get_kmodule_export("ntoskrnl.exe", "PsGetProcessPeb");

            return this->syscall<PPEB(*)(PEPROCESS)>(get_peb, get_peprocess(pid));
        }

    private:
        void locate_syscall(std::uintptr_t begin, std::uintptr_t end) const;
        bool valid_syscall(void* syscall_addr) const;

        read_phys_t read_phys;
        write_phys_t write_phys;
    };
}