#include "memory.hpp"

#include "../lib/voyager-sdk/include/voyager/voyager.hpp"
#include "../include/vdm/vdm.hpp"

#include <string>
#include <Psapi.h>


struct baseEntry {
    uint64_t base;
    const wchar_t* name;
};
typedef struct _k_get_base_module_request {
    ULONG pid;
    ULONGLONG handle;
    WCHAR name[260];
} k_get_base_module_request, * pk_get_base_module_request;
std::vector<baseEntry> moduleBaseCache;

std::wstring charToWchar(const char* input) {
    const size_t size = strlen(input) + 1;
    std::wstring input_w = std::wstring(size, L'#');
    mbstowcs_s((size_t*)NULL, &input_w[0], size, input, size);
    return input_w;
}
namespace memory {
    uint32_t _pid = 0;
    voyager::guest_phys_t _dirbase = 0;
    vdm::vdm_ctx _vdm;

    typedef struct _PEB32 {
        BYTE reserved_0[2];
        BYTE is_debugging;
        BYTE reserved_1[1];
        uint32_t image;
        uint32_t ldr;
    } PEB32;

    typedef struct _PEB64 {
        BYTE reserved_0[2];
        BYTE is_debugging;
        BYTE reserved_1[13];
        uint64_t image;
        uint64_t ldr;
    } PEB64;

#ifdef _WIN64

    using PEB = PEB64;

#else

    using peb_t = PEB32;

#endif

    vdm::read_phys_t _read_phys = [](void* addr, void* buffer, std::size_t size) -> bool {
        const auto read_result = voyager::read_phys((u64)addr, (u64)buffer, size);

        return read_result == voyager::vmxroot_error_t::error_success;
    };

    vdm::write_phys_t _write_phys = [](void* addr, void* buffer, std::size_t size) -> bool {
        const auto write_result = voyager::write_phys((u64)addr, (u64)buffer, size);

        return write_result == voyager::vmxroot_error_t::error_success;
    };

    bool initialize() {
        if (voyager::init() != voyager::vmxroot_error_t::error_success)
            return false;

        _vdm = vdm::vdm_ctx(_read_phys, _write_phys);

        return true;
    }

  

    bool read(uint64_t address, void* buffer, size_t size) {
        return voyager::copy_virt(_dirbase, address, voyager::current_dirbase(), reinterpret_cast<uint64_t>(buffer), size) == voyager::vmxroot_error_t::error_success;
    }

    bool write(uint64_t address, const void* buffer, size_t size) {
        return voyager::copy_virt(voyager::current_dirbase(), reinterpret_cast<uint64_t>(buffer), _dirbase, address, size) == voyager::vmxroot_error_t::error_success;
    }

   

}

