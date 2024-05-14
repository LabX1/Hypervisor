#ifndef _MEMORY_HPP_
#define _MEMORY_HPP_

#include <iostream>
#include <vector>
#include <memory>

#pragma once
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <ntstatus.h>
#include <iostream>
#include <io.h>
#include <stdlib.h>
#include <cstdint>
#include <string_view>
#include <algorithm>
#include <string_view>
#include <tlhelp32.h>
#include <map>
//#include "nt.hpp"
#include <fcntl.h>
//#include "../xorstr.hpp"
#include <winternl.h>
#include "../include/vdm/vdm.hpp"

namespace memory {
    bool initialize();

  //  uint64_t getModuleBase(const char* moduleName);
    bool read(uint64_t address, void* buffer, size_t size);
    bool write(uint64_t address, const void* buffer, size_t size);

    template <typename T>
    T read(uint64_t address) {
        T result;
        if (!read(address, &result, sizeof(T)))
            return T();
        return result;
    }

    template <typename T>
    T readArray(uint64_t address, size_t len) {
        T result;
        if (!read(address, &result, sizeof(T) * len))
            return T();
        return result;
    }

    template <typename T>
    bool write(uint64_t address, const T value) {
        return write(address, &value, sizeof(T));
    }



}

#define FIELD(T, NAME, OFFSET) inline element<T> NAME() { return element<T>(*reinterpret_cast<T*>(&this->data[OFFSET]), this->address + OFFSET) }
#define SYNC_FIELD(T, NAME, OFFSET) inline element<T, true> NAME() { return element<T, true>(*reinterpret_cast<T*>(&this->data[OFFSET]), this->address + OFFSET); }
#define SYNC_FIELD_STRUCT(T, NAME, OFFSET) inline element<T, true> NAME() { \
        auto& value = *reinterpret_cast<T*>(&this->data[OFFSET]);           \
        value.address = this->address + OFFSET;                             \
        return element<T, true>(value, this->address + OFFSET); \
    }

template <size_t N>
struct memory_block {
    uint8_t data[N];

    inline uint8_t& operator [](size_t index) {
        return this->data[index];
    }

    [[nodiscard]] inline size_t size() const {
        return N;
    }
};

template <size_t N>
struct sync_block : public memory_block<N> {
    uint64_t address;

    sync_block() = default;

    explicit sync_block(uint64_t address) : address(address) {
        (void) this->read();
    }

    bool read() {
        return memory::read(this->address, this->data, N);
    }

    bool write() {
        return memory::write(address, this->data, N);
    }
};

template <typename T, bool SYNC = false>
struct element {
    T& value;
    uint64_t address;

    element(T& value, uint64_t address) : value(value), address(address) { }

    element& operator =(const element& other) {
        if constexpr (SYNC) {
            memory::write<T>(address, other.value);
        }

        *this = other;

        return *this;
    }

    element& operator =(const T other) {
        if constexpr (SYNC) {
            memory::write<T>(address, other);
        }

        this->value = other;

        return *this;
    }
};

#endif