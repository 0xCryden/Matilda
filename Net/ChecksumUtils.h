#pragma once

#include <cstdint>
#include <cstddef>

// Lightweight helpers for network byte-order reads/writes and checksums.
uint16_t ones_complement_checksum(const uint8_t* buf, size_t len);
void write_u16_be(uint8_t* buf, uint16_t v);
void write_u32_be(uint8_t* buf, uint32_t v);
uint16_t read_u16_be(const uint8_t* buf);
uint32_t read_u32_be(const uint8_t* buf);
