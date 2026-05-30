#include "PacketStore.h"
#include <algorithm>

PacketStore::PacketStore()
{
}

PacketStore::~PacketStore()
{
    // free RawPacketVector contents if necessary
    std::lock_guard<std::mutex> lk(m_lock);
    for (size_t i = 0; i < m_packets.size(); ++i) {
        pcpp::RawPacket* p = m_packets.at(i);
        if (p) delete p;
    }
    m_packets.clear();
}

void PacketStore::appendPacket(pcpp::RawPacket* p, const std::vector<std::string>& meta)
{
    std::lock_guard<std::mutex> lk(m_lock);
    if (p) m_packets.push_back(p);
    m_meta.emplace_back(meta);
}

void PacketStore::appendOutgoing(const std::vector<uint8_t>& frame, const std::vector<std::string>& meta)
{
    std::lock_guard<std::mutex> lk(m_lock);
    pcpp::RawPacket* rp = new pcpp::RawPacket();
    timeval tv{}; tv.tv_sec = 0; tv.tv_usec = 0;
    if (!rp->setRawData(frame.data(), (int)frame.size(), false, tv, pcpp::LINKTYPE_ETHERNET)) {
        delete rp; return;
    }
    m_packets.push_back(rp);
    m_meta.emplace_back(meta);
}

size_t PacketStore::getCount() const
{
    std::lock_guard<std::mutex> lk(m_lock);
    return m_packets.size();
}

bool PacketStore::getPacketBytes(size_t index, std::vector<uint8_t>& out) const
{
    std::lock_guard<std::mutex> lk(m_lock);
    if (index >= m_packets.size()) return false;
    pcpp::RawPacket* p = m_packets.at(index);
    if (!p) return false;
    const uint8_t* data = p->getRawData();
    int len = p->getRawDataLen();
    out.assign(data, data + len);
    return true;
}

bool PacketStore::getMeta(size_t index, std::vector<std::string>& out) const
{
    std::lock_guard<std::mutex> lk(m_lock);
    if (index >= m_meta.size()) return false;
    out = m_meta[index];
    return true;
}

pcpp::RawPacket* PacketStore::clonePacket(size_t index) const
{
    std::lock_guard<std::mutex> lk(m_lock);
    if (index >= m_packets.size()) return nullptr;
    pcpp::RawPacket* orig = m_packets.at(index);
    if (!orig) return nullptr;
    try {
        return new pcpp::RawPacket(*orig);
    }
    catch (...) { return nullptr; }
}
