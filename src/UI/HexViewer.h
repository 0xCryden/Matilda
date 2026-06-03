#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <cstddef>

// HexViewer: encapsulates hex dump formatting and range highlighting.
// Role: format hex dump string for given bytes and expose HighlightHexRange behavior.
// Used by ParsedPanel on field selection updates.
class HexViewer
{
public:
    // Format bytes as hex dump with offset/hex/ascii columns.
    // Returns formatted string suitable for EDIT control.
    static std::string formatHexDump(const std::vector<uint8_t>& bytes);

    // Highlight a byte range in the hex dump (via EDIT control selection).
    // hEditCtl: the EDIT control displaying the hex dump
    // byteOffset: starting byte index
    // byteLen: number of bytes to highlight
    static void highlightByteRange(HWND hEditCtl, size_t byteOffset, size_t byteLen);

    // Get the character position in hex dump for a given byte offset.
    // Used for selection calculation.
    static int byteOffsetToHexCharPos(size_t byteOffset);
};
