#include "CaptureDevice.h"
#include "PcapLiveDevice.h"

CaptureDevice::CaptureDevice(pcpp::PcapLiveDevice* device)
    : m_device(device), m_isOpen(false)
{
}

CaptureDevice::~CaptureDevice()
{
    close();
}

bool CaptureDevice::open()
{
    if (!m_device) return false;
    if (m_isOpen) return true;
    
    m_isOpen = m_device->open();
    return m_isOpen;
}

void CaptureDevice::close()
{
    if (!m_device || !m_isOpen) return;
    
    m_device->close();
    m_isOpen = false;
}

bool CaptureDevice::isOpen() const
{
    return m_isOpen;
}

void CaptureDevice::startCapture(CaptureCallback callback, void* userData)
{
    if (!m_device) return;
    m_device->startCapture(callback, userData);
}

void CaptureDevice::stopCapture()
{
    if (!m_device) return;
    m_device->stopCapture();
}

pcpp::PcapLiveDevice* CaptureDevice::getDevice() const
{
    return m_device;
}
