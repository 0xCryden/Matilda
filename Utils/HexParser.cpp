#include "HexParser.h"
#include <cctype>

bool parseHexString(const std::string& s, std::vector<uint8_t>& out)
{
    out.clear();
    std::string tmp;
    for (char c : s) { if (!isspace((unsigned char)c)) tmp.push_back(c); }
    if (tmp.size() % 2 != 0) return false;
    for (size_t i = 0; i < tmp.size(); i += 2)
    {
        auto hexval = [](char c)->int {
            if (c >= '0' && c <= '9') return c - '0';
            if (c >= 'a' && c <= 'f') return 10 + (c - 'a');
            if (c >= 'A' && c <= 'F') return 10 + (c - 'A');
            return -1;
        };
        int hi = hexval(tmp[i]); int lo = hexval(tmp[i + 1]);
        if (hi < 0 || lo < 0) return false;
        out.push_back((uint8_t)((hi << 4) | lo));
    }
    return true;
}
