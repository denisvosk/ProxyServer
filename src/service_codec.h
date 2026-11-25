#pragma once
#include "service_host.h"
#include <cstddef>
#include <vector>

namespace service_host { namespace codec {
using Bytes = std::vector<unsigned char>;
const std::size_t MaxPayload = 262144;
const std::uint32_t Version = 1;
const std::uint32_t WireMagic = 0x31325350; // PS21, little-endian.
struct Writer {
    Bytes data;
    bool ok = true;
    void u8(unsigned value);
    void u16(unsigned value);
    void u32(std::uint32_t value);
    void u64(std::uint64_t value);
    void boolean(bool value);
    void text(const std::string& value);
    void bytes(const Bytes& value);
};
struct Reader {
    const Bytes& data;
    std::size_t position = 0;
    bool ok;
    explicit Reader(const Bytes& input);
    bool u8(unsigned& value);
    bool u16(unsigned short& value);
    bool u32(std::uint32_t& value);
    bool u64(std::uint64_t& value);
    bool boolean(bool& value);
    bool text(std::string& value);
    bool bytes(Bytes& value);
    bool done() const;
};
bool encodeProfile(const Profile& profile, Bytes& output);
bool decodeProfile(const Bytes& input, Profile& profile);
bool encodeState(const State& state, Bytes& output);
bool decodeState(const Bytes& input, State& state);
void erase(Bytes& bytes);
void erase(Profile& profile);
} }
