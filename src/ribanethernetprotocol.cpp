#include "ribanethernetprotocol.h"

ribanEthernetProtocol::ribanEthernetProtocol(ribanEthernetProtocol* pParent) :
    m_nSendPacketLen(0),
    m_pParent(pParent)
{
    Init();
}

ribanEthernetProtocol::~ribanEthernetProtocol()
{
}

void ribanEthernetProtocol::Init()
{
}

uint16_t ribanEthernetProtocol::Process(byte* pBuffer, uint16_t nLen)
{
    return 0;
}

uint16_t ribanEthernetProtocol::CreateChecksum(byte* pData, uint16_t nLen)
{
    //Sum all 16-bit words
    uint32_t nSum = 0;
    for(uint16_t i = 0; i < nLen; i += 2)
    {
        if(i < nLen)
            nSum += (uint16_t)((uint32_t)((*(pData + i) << 8) | *(pData + i + 1)));
        else
            nSum += (uint16_t)((uint32_t)((*(pData + i) << 8))); //Catch odd number of data (last octet)
    }
    //Sum all 16-bit words of result
    while(nSum >> 16)
        nSum = (uint16_t)nSum + (nSum >> 16);
    //1's compliment
    return ~(uint16_t)nSum;
}

uint16_t ribanEthernetProtocol::GetPendingSend()
{
    uint16_t nLen = m_nSendPacketLen;
    m_nSendPacketLen = 0;
    return nLen;
}

void ribanEthernetProtocol::SendPacket(byte* pData, uint16_t nLen, byte* pDestination)
{
    TxListEntry listElement(pData, nLen);
    CascadeProtocol(&listElement);
}

void ribanEthernetProtocol::CascadeProtocol(TxListEntry* pList)
{
    if(m_pParent)
    {
        //!@todo Add protocol header
        byte* pHeader = NULL;
        uint16_t nLen = 0;
        TxListEntry listElement(pHeader, nLen, pList);
        m_pParent->CascadeProtocol(&listElement);
    }
}
