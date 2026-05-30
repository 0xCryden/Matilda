#include <WinSock2.h>
#include <Ws2tcpip.h>
#include "CaptureManager.h"
#include <ctime>
#include <sstream>

// Helper: 16-bit ones-complement checksum over buffer (pads odd length with zero). Calculates over bytes (network order interpretation)
static uint16_t ones_complement_checksum(const uint8_t* buf, size_t len)
{
	uint32_t sum = 0;
	size_t i = 0;
	while (i + 1 < len)
	{
		uint16_t word = (uint16_t)((buf[i] << 8) | buf[i + 1]);
		sum += word;
		i += 2;
	}
	if (i < len)
	{
		uint16_t word = (uint16_t)(buf[i] << 8);
		sum += word;
	}
	// fold
	while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
	return (uint16_t)(~sum & 0xFFFF);
}

// Helper: write uint16_t in network order into buffer
static void write_u16_be(uint8_t* buf, uint16_t v)
{
	buf[0] = (uint8_t)((v >> 8) & 0xFF);
	buf[1] = (uint8_t)(v & 0xFF);
}

// Sends a captured packet unchanged (kept for backward compatibility)
bool CaptureManager::sendCapturedPacket(size_t index)
{
	if (!m_currentDevice || index >= m_capturedPackets.size())
		return false;

	pcpp::RawPacketVector tmp;
	// copy the captured packet into a new RawPacket owned by tmp
	try {
		tmp.pushBack(new pcpp::RawPacket(*m_capturedPackets.at((int)index)));
	}
	catch (...) { return false; }

	int sent = m_currentDevice->sendPackets(tmp);
	return sent == 1;
}

// Sends a captured packet but replaces the transport payload with the provided payload bytes.
// If payload is empty, the original packet payload is used (behaves like sendCapturedPacket).
// errOut, if provided, will receive a textual error on failure.
bool CaptureManager::sendCapturedPacketWithPayload(size_t index, const std::vector<uint8_t>& payload, const std::string& protoOverride, const std::string& srcIpOverride, uint16_t srcPortOverride, const std::string& dstIpOverride, uint16_t dstPortOverride, std::string* errOut)
{
	try {
		if (!m_currentDevice) {
			if (errOut) *errOut = "No device selected/open";
			return false;
		}
		if (index >= m_capturedPackets.size()) {
			if (errOut) *errOut = "Invalid packet index";
			return false;
		}

		pcpp::RawPacket* orig = m_capturedPackets.at((int)index);
		if (!orig) { if (errOut) *errOut = "Original packet missing"; return false; }

		const uint8_t* origData = orig->getRawData();
		int origLen = orig->getRawDataLen();
		if (origLen <= 0) { if (errOut) *errOut = "Original packet has zero length"; return false; }

		std::vector<uint8_t> data(origData, origData + origLen);

		// Minimal Ethernet + IPv4 + (TCP|UDP) handling. If packet is not IPv4, fallback to sending original or new raw data wrapper.
		const size_t ethHeaderLen = 14;
		if (data.size() < ethHeaderLen + 20) {
			// Too small to parse IPv4; just replace payload by appending payload to original and send raw
			if (payload.empty()) {
				{
					pcpp::RawPacketVector v;
					v.pushBack(new pcpp::RawPacket(*orig));
					int sent = m_currentDevice->sendPackets(v);
					if (sent != 1 && errOut) *errOut = "sendPackets failed";
					return sent == 1;
				}
			}
			else {
				// append payload to original frame and send
				std::vector<uint8_t> out = data;
				out.insert(out.end(), payload.begin(), payload.end());
				bool ok = sendRawPacket(out);
				if (!ok && errOut) *errOut = "sendRawPacket failed";
				return ok;
			}
		}

		uint16_t ethType = (uint16_t)((data[12] << 8) | data[13]);
		if (ethType != 0x0800) {
			// not IPv4
			if (payload.empty()) {
				{
					pcpp::RawPacketVector v;
					v.pushBack(new pcpp::RawPacket(*orig));
					int sent = m_currentDevice->sendPackets(v);
					if (sent != 1 && errOut) *errOut = "sendPackets failed (non-IPv4)";
					return sent == 1;
				}
			}
			std::vector<uint8_t> out = data;
			out.insert(out.end(), payload.begin(), payload.end());
			bool ok = sendRawPacket(out);
			if (!ok && errOut) *errOut = "sendRawPacket failed (non-IPv4)";
			return ok;
		}

		size_t ipOffset = ethHeaderLen;
		uint8_t verIhl = data[ipOffset];
		uint8_t ihl = verIhl & 0x0F;
		size_t ipHeaderLen = (size_t)ihl * 4;
		if (ipHeaderLen < 20 || data.size() < ipOffset + ipHeaderLen) { if (errOut) *errOut = "Invalid IPv4 header"; return false; }

		uint8_t protocol = data[ipOffset + 9];

		size_t transportOffset = ipOffset + ipHeaderLen;
		if (data.size() < transportOffset) { if (errOut) *errOut = "Invalid transport offset"; return false; }

		// Determine transport header length and payload offset
		size_t transHeaderLen = 0;
		size_t payloadOffset = 0;

		if (protocol == 6) // TCP
		{
			if (data.size() < transportOffset + 20) { if (errOut) *errOut = "TCP header truncated"; return false; }
			uint8_t dataOffsetByte = data[transportOffset + 12];
			uint8_t tcpDataOffset = (dataOffsetByte >> 4) & 0x0F;
			transHeaderLen = (size_t)tcpDataOffset * 4;
			if (transHeaderLen < 20) transHeaderLen = 20;
			payloadOffset = transportOffset + transHeaderLen;
		}
		else if (protocol == 17) // UDP
		{
			if (data.size() < transportOffset + 8) { if (errOut) *errOut = "UDP header truncated"; return false; }
			transHeaderLen = 8;
			payloadOffset = transportOffset + transHeaderLen;
		}
		else
		{
			// Unknown transport; treat as opaque and append payload if provided
			if (payload.empty()) {
				pcpp::RawPacketVector v; v.pushBack(new pcpp::RawPacket(*orig));
				int sent = m_currentDevice->sendPackets(v);
				if (sent != 1 && errOut) *errOut = "sendPackets failed (unknown proto)";
				return sent == 1;
			}
			std::vector<uint8_t> out = data;
			out.insert(out.end(), payload.begin(), payload.end());
			bool ok = sendRawPacket(out);
			if (!ok && errOut) *errOut = "sendRawPacket failed (unknown proto)";
			return ok;
		}

		// Determine payload bytes to use
		std::vector<uint8_t> newPayload;
		if (payload.empty())
		{
			// use original payload
			if (data.size() > payloadOffset)
				newPayload.assign(data.begin() + payloadOffset, data.end());
			else
				newPayload.clear();
		}
		else
		{
			newPayload = payload;
		}

		// Build new frame: keep headers up to payloadOffset, then append newPayload
		std::vector<uint8_t> out;
		out.insert(out.end(), data.begin(), data.begin() + payloadOffset);
		out.insert(out.end(), newPayload.begin(), newPayload.end());

		// Apply optional overrides: src/dst IPs and ports. Only supports same-protocol modifications (no TCP<->UDP conversion).
		if (!protoOverride.empty()) {
			// allow only if matches existing protocol
			if ((protoOverride == "TCP" && protocol != 6) || (protoOverride == "UDP" && protocol != 17)) {
				if (errOut) *errOut = "Protocol override not supported for this packet";
				return false;
			}
		}

		// IP overrides
		if (!srcIpOverride.empty()) {
			in_addr a{};
			if (inet_pton(AF_INET, srcIpOverride.c_str(), &a) == 1) {
				if (out.size() >= ipOffset + 16) {
					memcpy(&out[ipOffset + 12], &a.S_un.S_addr, 4);
				}
			}
			else {
				if (errOut) *errOut = "Invalid source IP override"; return false;
			}
		}
		if (!dstIpOverride.empty()) {
			in_addr a{};
			if (inet_pton(AF_INET, dstIpOverride.c_str(), &a) == 1) {
				if (out.size() >= ipOffset + 20) {
					memcpy(&out[ipOffset + 16], &a.S_un.S_addr, 4);
				}
			}
			else {
				if (errOut) *errOut = "Invalid destination IP override"; return false;
			}
		}

		// Port overrides
		if (srcPortOverride != 0) {
			if (out.size() >= transportOffset + 2) {
				write_u16_be(&out[transportOffset], srcPortOverride);
			}
			else { if (errOut) *errOut = "Frame too small for source port override"; return false; }
		}
		if (dstPortOverride != 0) {
			if (out.size() >= transportOffset + 4) {
				write_u16_be(&out[transportOffset + 2], dstPortOverride);
			}
			else { if (errOut) *errOut = "Frame too small for destination port override"; return false; }
		}

		// Update IPv4 total length field (in bytes) = ipHeaderLen + transport header len + payload len
		uint16_t newIpTotalLen = (uint16_t)(ipHeaderLen + transHeaderLen + newPayload.size());
		if (out.size() < ipOffset + 4) { if (errOut) *errOut = "Unexpected frame size when updating IP length"; return false; }
		write_u16_be(&out[ipOffset + 2], newIpTotalLen);

		// Recompute IPv4 header checksum
		if (out.size() < ipOffset + ipHeaderLen) { if (errOut) *errOut = "Unexpected frame size when computing IP checksum"; return false; }
		out[ipOffset + 10] = 0; out[ipOffset + 11] = 0;
		uint16_t ipCsum = ones_complement_checksum(&out[ipOffset], ipHeaderLen);
		write_u16_be(&out[ipOffset + 10], ipCsum);

		// Recompute transport checksum (TCP/UDP) using pseudo-header
		// Pseudo-header: src IP (4), dst IP (4), zero (1), protocol (1), tcp/udp length (2)
		if (out.size() < ipOffset + 20) { if (errOut) *errOut = "IPv4 header too small for pseudo-header"; return false; }
		uint8_t srcIp[4], dstIp[4];
		memcpy(srcIp, &out[ipOffset + 12], 4);
		memcpy(dstIp, &out[ipOffset + 16], 4);

		uint16_t transportLen = (uint16_t)(transHeaderLen + newPayload.size());

		if (protocol == 6) // TCP
		{
			size_t tcpCsumOffset = transportOffset + 16;
			if (out.size() < tcpCsumOffset + 2) { if (errOut) *errOut = "Frame too small for TCP checksum"; return false; }
			out[tcpCsumOffset] = 0; out[tcpCsumOffset + 1] = 0;

			// Build buffer for checksum: pseudo-header + tcp header + payload
			std::vector<uint8_t> cbuf;
			cbuf.insert(cbuf.end(), srcIp, srcIp + 4);
			cbuf.insert(cbuf.end(), dstIp, dstIp + 4);
			cbuf.push_back(0);
			cbuf.push_back(protocol);
			uint8_t tlenb[2]; write_u16_be(tlenb, transportLen);
			cbuf.push_back(tlenb[0]); cbuf.push_back(tlenb[1]);
			// append tcp header+payload
			if (out.size() < transportOffset + transHeaderLen) { if (errOut) *errOut = "Frame too small for TCP header"; return false; }
			cbuf.insert(cbuf.end(), out.begin() + transportOffset, out.begin() + transportOffset + transHeaderLen);
			if (!newPayload.empty()) cbuf.insert(cbuf.end(), newPayload.begin(), newPayload.end());

			uint16_t tcpCsum = ones_complement_checksum(cbuf.data(), cbuf.size());
			write_u16_be(&out[tcpCsumOffset], tcpCsum);
		}
		else if (protocol == 17) // UDP
		{
			size_t udpLenFieldOffset = transportOffset + 4;
			size_t udpCsumOffset = transportOffset + 6;
			if (out.size() < udpCsumOffset + 2) { if (errOut) *errOut = "Frame too small for UDP header"; return false; }
			// set udp length
			write_u16_be(&out[udpLenFieldOffset], (uint16_t)transportLen);
			// set checksum to 0 before calculation
			out[udpCsumOffset] = 0; out[udpCsumOffset + 1] = 0;

			// Build pseudo-header + udp header + payload
			std::vector<uint8_t> cbuf;
			cbuf.insert(cbuf.end(), srcIp, srcIp + 4);
			cbuf.insert(cbuf.end(), dstIp, dstIp + 4);
			cbuf.push_back(0);
			cbuf.push_back(protocol);
			uint8_t tlenb[2]; write_u16_be(tlenb, transportLen);
			cbuf.push_back(tlenb[0]); cbuf.push_back(tlenb[1]);
			// append udp header and payload
			if (out.size() < transportOffset + transHeaderLen) { if (errOut) *errOut = "Frame too small for UDP header"; return false; }
			cbuf.insert(cbuf.end(), out.begin() + transportOffset, out.begin() + transportOffset + transHeaderLen);
			if (!newPayload.empty()) cbuf.insert(cbuf.end(), newPayload.begin(), newPayload.end());

			uint16_t udpCsum = ones_complement_checksum(cbuf.data(), cbuf.size());
			// UDP checksum of 0 means not used; but IPv4 allows 0. Use calculated value
			write_u16_be(&out[udpCsumOffset], udpCsum);
		}

		// ------------------------------------------------------------------
		// TCP sequence / acknowledgement correction
		// When we send with a (possibly modified) payload we must advance the
		// sequence number so the server doesn't treat it as a retransmission
		// or an out-of-window segment.
		//
		// Strategy:
		//   new_seq = original_seq + original_payload_length
		//             (i.e. "we already sent the original payload, now we
		//              are sending the next segment")
		//   ack stays the same (we haven't received more from the peer)
		//   window: use a generous fixed value so the server doesn't think
		//           our receive buffer is full
		// ------------------------------------------------------------------
		if (protocol == 6 && out.size() >= transportOffset + 20)
		{
			// original payload length in the captured packet
			size_t origPayloadLen = (data.size() > payloadOffset) ? (data.size() - payloadOffset) : 0;

			// read original seq
			uint32_t origSeq = ((uint32_t)data[transportOffset+4] << 24)
			                 | ((uint32_t)data[transportOffset+5] << 16)
			                 | ((uint32_t)data[transportOffset+6] <<  8)
			                 |  (uint32_t)data[transportOffset+7];

			uint32_t newSeq = origSeq + (uint32_t)origPayloadLen;

			// write new seq into out (network order)
			out[transportOffset+4] = (uint8_t)(newSeq >> 24);
			out[transportOffset+5] = (uint8_t)(newSeq >> 16);
			out[transportOffset+6] = (uint8_t)(newSeq >>  8);
			out[transportOffset+7] = (uint8_t)(newSeq      );

			// Set window size to 65535 (generous, avoids zero-window rejection)
			out[transportOffset+14] = 0xFF;
			out[transportOffset+15] = 0xFF;

			// If TCP data-offset > 5 there are options.  We keep them as-is
			// since timestamps etc. are harmless to re-send unchanged.
		}
		// internal copy of the data. Passing true hands ownership of out.data() to the
		// RawPacket, but that pointer belongs to a std::vector on our stack — when the
		// RawPacketVector v destructs it would delete[] our vector's buffer, causing the
		// heap corruption / __debugbreak seen in _Deallocate.
		pcpp::RawPacket* rp = new pcpp::RawPacket();
		timeval tv{}; tv.tv_sec = 0; tv.tv_usec = 0;
		if (!rp->setRawData(out.data(), (int)out.size(), false, tv, pcpp::LINKTYPE_ETHERNET))
		{
			delete rp; if (errOut) *errOut = "Failed to create RawPacket"; return false;
		}
		pcpp::RawPacketVector v; v.pushBack(rp);
		int sent = m_currentDevice->sendPackets(v);
		if (sent != 1) {
			if (errOut) *errOut = "sendPackets failed";
			return false;
		}

		// Build meta and log outgoing packet into capture lists so UI shows it
		try {
			std::vector<std::string> meta;
			// time
			SYSTEMTIME st{}; GetLocalTime(&st);
			char timestr[64]; snprintf(timestr, sizeof(timestr), "%02d:%02d:%02d.%03d", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
			meta.push_back(timestr);
			meta.push_back(std::string("Sent"));
			meta.push_back((protocol == 6) ? std::string("TCP") : ((protocol == 17) ? std::string("UDP") : std::string("OTHER")));

			// extract src/dst IP and ports from out
			std::string srcIpStr, dstIpStr; std::string srcPortStr, dstPortStr;
			if (out.size() >= ipOffset + 20) {
				char buf[64];
				auto sip = &out[ipOffset + 12];
				auto dip = &out[ipOffset + 16];
				snprintf(buf, sizeof(buf), "%u.%u.%u.%u", sip[0], sip[1], sip[2], sip[3]); srcIpStr = buf;
				snprintf(buf, sizeof(buf), "%u.%u.%u.%u", dip[0], dip[1], dip[2], dip[3]); dstIpStr = buf;
				if (out.size() >= transportOffset + 4) {
					uint16_t sport = (uint16_t)((out[transportOffset] << 8) | out[transportOffset+1]);
					uint16_t dport = (uint16_t)((out[transportOffset+2] << 8) | out[transportOffset+3]);
					srcPortStr = std::to_string(sport);
					dstPortStr = std::to_string(dport);
				}
			}
			meta.push_back(srcIpStr);
			meta.push_back(srcPortStr);
			meta.push_back(dstIpStr);
			meta.push_back(dstPortStr);
			meta.push_back(std::to_string(out.size()));
			meta.push_back(std::string("(Matilda)")); // proc: marks manually sent packet

			logOutgoingPacket(out, meta);
		} catch(...) { }

		return true;
	}
	catch (const std::exception& ex) {
		if (errOut) *errOut = std::string("exception: ") + ex.what();
		return false;
	}
	catch (...) {
		if (errOut) *errOut = "unknown exception";
		return false;
	}
}

// Log an outgoing frame into internal captured lists and post a UI notification similarly to live capture batching
bool CaptureManager::logOutgoingPacket(const std::vector<uint8_t>& frame, const std::vector<std::string>& meta)
{
	int newIdx = -1;
	std::vector<uint8_t> realFrame = frame;
	bool usedPlaceholder = false;
	if (realFrame.empty()) {
		// create minimal placeholder ethernet frame so we can store a RawPacket
		realFrame.assign(14, 0);
		usedPlaceholder = true;
	}
	try {
		std::lock_guard<std::mutex> lk(m_capturedLock);
		pcpp::RawPacket* rp = new pcpp::RawPacket();
		timeval tv{}; tv.tv_sec = 0; tv.tv_usec = 0;
		// Pass deleteRawDataAtDestructor=false: realFrame is a local vector on our stack.
		// Passing true would give m_capturedPackets ownership of realFrame's internal buffer
		// pointer; when realFrame destructs at end of this scope it would free the same memory,
		// causing a double-free later when m_capturedPackets tries to delete[] it.
		if (!rp->setRawData(realFrame.data(), (int)realFrame.size(), false, tv, pcpp::LINKTYPE_ETHERNET)) { delete rp; return false; }
		m_capturedPackets.pushBack(rp);
		newIdx = (int)(m_capturedPackets.size() - 1);
		if (m_capturedMeta.size() <= (size_t)newIdx) m_capturedMeta.resize(newIdx + 1);
		m_capturedMeta[newIdx] = meta;
	}
	catch (...) { return false; }

	// build summary string similar to capture code
	std::ostringstream out;
	// meta expected: time, dir, proto, srcIp, srcPort, dstIp, dstPort, len, proc
	for (size_t i = 0; i < meta.size() && i < 9; ++i) {
		out << meta[i] << '\t';
	}
	// show 0 length for placeholder (original intent was to show actual frame len)
	out << (usedPlaceholder ? 0 : (int)frame.size()) << '\t';
	out << "\t---------------------\r\n";

	if (m_uiWindow) {
		struct PktMsg { int idx; char* summary; };
		PktMsg* arr = new PktMsg[1];
		arr[0].idx = newIdx;
		arr[0].summary = _strdup(out.str().c_str());
		PostMessageA((HWND)m_uiWindow, WM_APP + 2, (WPARAM)1, (LPARAM)arr);
	}
	return true;
}


bool CaptureManager::sendRawPacket(const std::vector<uint8_t>& data)
{
	if (!m_currentDevice || data.empty())
		return false;

	// create a raw packet instance and set its data.
	// Pass deleteRawDataAtDestructor=false: data.data() points into the caller's vector;
	// PcapPlusPlus must make its own copy rather than taking ownership of that pointer.
	pcpp::RawPacket* p = new pcpp::RawPacket();
	timeval tv{};
	tv.tv_sec = 0;
	tv.tv_usec = 0;
	if (!p->setRawData(data.data(), (int)data.size(), false, tv, pcpp::LINKTYPE_ETHERNET))
	{
		delete p;
		return false;
	}

	pcpp::RawPacketVector tmp;
	tmp.pushBack(p);
	int sent = m_currentDevice->sendPackets(tmp);
	return sent == 1;
}

size_t CaptureManager::getCapturedCount() const
{
	std::lock_guard<std::mutex> lk(m_capturedLock);
	return m_capturedPackets.size();
}

bool CaptureManager::getCapturedMeta(size_t index, std::vector<std::string>& out) const
{
	std::lock_guard<std::mutex> lk(m_capturedLock);
	if (index >= m_capturedMeta.size()) return false;
	out = m_capturedMeta[index];
	return true;
}

bool CaptureManager::setFilter(const std::string& filter)
{
	if (!m_currentDevice)
		return false;

	// Use PcapPlusPlus helper
	return m_currentDevice->setFilter(filter);
}

bool CaptureManager::getCapturedPacketBytes(size_t index, std::vector<uint8_t>& out) const
{
	std::lock_guard<std::mutex> lk(m_capturedLock);
	if (index >= m_capturedPackets.size())
		return false;
	pcpp::RawPacket* p = m_capturedPackets.at((int)index);
	if (!p) return false;
	const uint8_t* data = p->getRawData();
	int len = p->getRawDataLen();
	out.assign(data, data + len);
	return true;
}
