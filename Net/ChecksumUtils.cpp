#include "Net/ChecksumUtils.h"
#include <cstdint>
#include <cstddef>

uint16_t ones_complement_checksum(const uint8_t* buf, size_t len)
{
    uint32_t sum = 0;
    size_t i = 0;
    while (i + 1 < len)
    {
        uint16_t word = (uint16_t)((buf[i] << 8) | buf[i + 1]);
        sum += word;
        i += 2;
    }
    if (i < len) sum += (uint16_t)(buf[i] << 8);
    while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
    return (uint16_t)(~sum & 0xFFFF);
}

void write_u16_be(uint8_t* buf, uint16_t v)
{
    buf[0] = (uint8_t)((v >> 8) & 0xFF);
    buf[1] = (uint8_t)(v & 0xFF);
}

void write_u32_be(uint8_t* buf, uint32_t v)
{
    buf[0] = (uint8_t)(v >> 24);
    buf[1] = (uint8_t)(v >> 16);
    buf[2] = (uint8_t)(v >> 8);
    buf[3] = (uint8_t)(v);
}

uint16_t read_u16_be(const uint8_t* buf)
{
    return (uint16_t)((buf[0] << 8) | buf[1]);
}

uint32_t read_u32_be(const uint8_t* buf)
{
    return ((uint32_t)buf[0] << 24) | ((uint32_t)buf[1] << 16)
        | ((uint32_t)buf[2] << 8) | (uint32_t)buf[3];
}
