#include "ipv4.h"

void IPV4::Init()
{
    m_bIcmpEnabled = true;
    m_bUsingDhcp = true;
    m_nArpCursor = 2;
}

uint16_t IPV4::DoProcess(byte* pBuffer, uint16_t nLen)
{
    Serial.print("+");
    byte* pCursor = pBuffer + 2;
    //Check for ARP message
    if(nLen >= 30 && pBuffer[0] == 0x08 && pBuffer[1] == 0x06)
    {
        //Found ARP message
        if(pCursor[7] == 1)
        {
            //ARP request - Create response, reusing Rx buffer
            pCursor[7] = 2; //Change type to reply
            //Set MAC addresses
            memcpy(pCursor + 18, pCursor + 8, 6);
            memcpy(pCursor + 8, m_pLocalMac, 6);
            //Swap sender and target IP
            byte pTmp[4];
            memcpy(pTmp, pCursor + 14, 4);
            memcpy(pCursor + 14, pCursor + 24, 4);
            memcpy(pCursor + 24, pTmp, 4);
            TxListEntry txListEntry(pBuffer, 30);
            TxPacket(&txListEntry);
            Serial.print("Sent ARP reply to ");
            PrintIp(pTmp);
            Serial.println();
        }
        else if(pCursor[7] == 2)
        {
            //ARP reply
            for(byte i = 0; i < ARP_TABLE_SIZE; ++i)
            {
                if(0 == memcmp(pCursor + 14, m_aArpTable[i].ip, 4))
                {
                    memcpy(m_aArpTable[i].mac, pCursor + 8, 6);
                    break;
                }
            }
        }
        return nLen;
    }

    if(nLen < (IPV4_HEADER_SIZE + 2) || pBuffer[0] != 0x08 || pBuffer[1] != 0x00 || (pBuffer[2] & 0x40) != 0x40)
        return 0; //Not IPV4 packet

    //Get IPV4 header parameters
    uint16_t nHeaderLen = (pCursor[0] & 0x0F) * 4;
//    uint8_t nDSCP_ECN = pCursor[1]; //Not implemented in this library
//    uint16_t nTotalLen = (pCursor[2] << 8) + pCursor[3];
//    uint16_t nId =  (pCursor[4] << 8) + pCursor[5];
//    uint8_t nFlags = pCursor[6] & 0x60;
//    uint16_t nFragOffset = (pCursor[6] & 0x1F) << 8) + pCursor[7];
//    uint8_t nTtl = pCursor[8];
    m_nIpv4Protocol = pCursor[9];
//    uint16_t nChecksum = (pCursor[10] << 8) + pCursor[11];
    if(ribanEthernetProtocol::CreateChecksum(pCursor, nHeaderLen))
        return nLen; //Checksum error
        //!@todo Warn on checksum error
    memcpy(m_pRemoteIp, pCursor + 12, 4); //Store IP address of remote host
//    memcpy(m_pDestIp, pCursor[16], 4);
    if(nHeaderLen > 20)
        ; //!@todo Handle IPV4 options - Why bother in a small, embedded library?
    pCursor += nHeaderLen; //Point to start of IP payload
    if(ProcessIcmp(pCursor, nLen - nHeaderLen - 2))
        return nLen; //ICMP message so consume whole packet
    return nLen - nHeaderLen - 2; //Consume the Ethernet packet type (2) and header bytes
}

bool IPV4::ProcessIcmp(byte* pData, uint16_t nLen)
{
    if(nLen < ICMP_HEADER_SIZE)
        return false;
    byte nType = pData[0];
//    byte nCode = pData[1];
    if(ribanEthernetProtocol::CreateChecksum(pData, nLen))
        return true; //ICMP with invalid checksum
        //!@todo Create error on checksum error
    switch(nType)
    {
        case ICMP_TYPE_ECHOREPLY:
            //This is a response to an echo request (ping) so call our hanlder if defined
            if(m_pHandleEchoResponse)
                m_pHandleEchoResponse((*(pData + 6) << 8) + (*(pData + 7) & 0xFF)); //!@todo Pass parameters to handler?
            //!@todo This may be prone to DoS attack by targetting unsolicited echo responses at this host - may be less significant than limited recieve handling
            break;
        case ICMP_TYPE_ECHOREQUEST:
            if(m_bIcmpEnabled)
            {
                //This is an echo request (ping) from a remote host so send an echo reply (pong)
                //Reuse recieve buffer and send reply
                pData[0] = ICMP_TYPE_ECHOREPLY;
                pData[ICMP_CHECKSUM_OFFSET] = 0;
                pData[ICMP_CHECKSUM_OFFSET + 1] = 0;
                uint16_t nChecksum = ribanEthernetProtocol::CreateChecksum(pData, nLen);
                pData[ICMP_CHECKSUM_OFFSET] = nChecksum >> 8;;
                pData[ICMP_CHECKSUM_OFFSET + 1] = nChecksum & 0xFF;
                SendPacket(pData, nLen, IP_PROTOCOL_ICMP);
                break;
            }
        default:
            //Unhandled messgae types
            ;
    }
    return true; //Valid ICMP message
}

void IPV4::SendPacket(byte* pData, uint16_t nLen, byte nProtocol, byte* pDestination)
{
    TxListEntry pTxListEntry(pData, nLen);
    SendPacket(&pTxListEntry, nProtocol, pDestination);
}

void IPV4::SendPacket(TxListEntry* pTxListEntry, byte nProtocol, byte* pDestination)
{
    byte pHeader[IPV4_HEADER_SIZE + 2];
    memset(pHeader, 0, IPV4_HEADER_SIZE + 2);
    pHeader[0] = 0x08; //Populate IP version (4) and header size (5 32-bit words (=20))
    pHeader[2] = 0x45; //Populate IP version (4) and header size (5 32-bit words (=20))
    pHeader[4] = (IPV4_HEADER_SIZE + pTxListEntry->GetLen()) >> 8; //Populate total length
    pHeader[5] = (IPV4_HEADER_SIZE + pTxListEntry->GetLen()) & 0xFF;
    //!@todo We may be able to omit ipv4 packet identification which is mostly used for frameneted packets (which we do not create)
    pHeader[6] = m_nIdentification >> 8; //Populate packet identification
    pHeader[7] = m_nIdentification++ & 0xFF;
    pHeader[10] = 64; //Populate TTL - let's make it quite big as we don't really care how many hops this message takes
    pHeader[11] = nProtocol;
    memcpy(pHeader + IPV4_SOURCE_IP_OFFSET + 2, m_pLocalIp, 4); //Always send IPV4 packets from local host's IP address
    if(pDestination)
        memcpy(pHeader + IPV4_DESTINATION_IP_OFFSET + 2, pDestination, 4);
    else //use last recieved packet's source as (return) destination
        memcpy(pHeader + IPV4_DESTINATION_IP_OFFSET + 2, m_pRemoteIp, 4);
    uint16_t nChecksum = ribanEthernetProtocol::CreateChecksum(pHeader + 2, IPV4_HEADER_SIZE);
    pHeader[IPV4_CHECKSUM_OFFSET + 2] = nChecksum >> 8;
    pHeader[IPV4_CHECKSUM_OFFSET + 3] = nChecksum & 0xFF;

    TxListEntry txlistentryHeader(pHeader, IPV4_HEADER_SIZE + 2, pTxListEntry);
    //Figure out what IP & MAC address to target
    //!@todo Calculate destination:
    /*
    Is IP local host?
    Is IP last recieved packet?
    Is IP subnet broadcast? - Use FF:FF:FF:FF:FF:FF
    Is IP global broadcast? - Use FF:FF:FF:FF:FF:FF
    Is IP multicast? Use multicast address???
    Is IP withn subnet? Lookup remote host MAC
    Else use gateway router MAC
    */
    if(IsLocalIp(pHeader + IPV4_DESTINATION_IP_OFFSET + 2))
    {
        //Local host IP so ignore
        return;
    }
    else if(0 == memcmp(pHeader + IPV4_DESTINATION_IP_OFFSET + 2, m_pRemoteIp, 4))
    {
        //Same IP address as last recieved message so return to same MAC
        TxPacket(&txlistentryHeader, m_pRemoteMac);
        return;
    }
    else if(IsBroadcast(pHeader + IPV4_DESTINATION_IP_OFFSET + 2))
    {
        //Broadast IP so send to broadcast MAC
        byte pBroadcast[6] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF};
        TxPacket(&txlistentryHeader, pBroadcast);
        return;
    }
    else if(IsMulticast(pHeader + IPV4_DESTINATION_IP_OFFSET + 2))
    {
        //Multicast IP so send to multicast MAC
        //!@todo Send multicast packet
    }
    else if(IsOnLocalSubnet(pHeader + IPV4_DESTINATION_IP_OFFSET + 2))
    {
        //On local subnet so find MAC to send direct
        for(uint16_t i = 0; i < ARP_TABLE_SIZE + 2; ++i)
        {
            if(0 == memcmp(pHeader + IPV4_DESTINATION_IP_OFFSET + 2, m_aArpTable[i].ip, 4))
            {
                TxPacket(&txlistentryHeader, m_aArpTable[i].mac);
                return;
            }
        }
        //!@todo ARP lookup of remote host then (somehow) send message
        /*
        Send ARP lookup
        Populate Tx buffer using m_nic.TxBegin and m_nic.TxAppend
        Wait for reply
        If reply, send packet using m_nic.TxEnd
        */
        ArpLookup(pHeader + IPV4_DESTINATION_IP_OFFSET + 2);
    }
    else if(m_aArpTable[ARP_GATEWAY_INDEX].ip[0])
    {
        //Use gateway if it is defined
        TxPacket(&txlistentryHeader, m_aArpTable[ARP_GATEWAY_INDEX].mac);
    }
    else
    {
        //Haven't been able to send packet - what to do now?
    }
}

void IPV4::ConfigureStaticIp(const uint8_t* pIp,
                             const uint8_t* pGw,
                             const uint8_t* pDns,
                             const uint8_t* pNetmask)
{
    m_bUsingDhcp = false;
    if (pIp != 0)
        memcpy(m_pLocalIp, pIp, 4);
    if (pGw != 0)
    {
        memcpy(m_aArpTable[ARP_GATEWAY_INDEX].ip, pGw, 4);
        //!@todo lookup gw mac
    }
    if (pDns != 0)
        memcpy(m_aArpTable[ARP_DNS_INDEX].ip, pDns, 4);
        //!@todo lookup dns gw
    if(pNetmask != 0)
        memcpy(m_pNetmask, pNetmask, 4);
    //Update broadcast address
    for(byte i = 0; i < 4; ++i)
        m_pBroadcastIp[i] = m_pLocalIp[i] | ~m_pNetmask[i];
    //Update subnet address
    for(byte i = 0; i < 4; ++i)
        m_pSubnetIp[i] = m_pLocalIp[i] & m_pNetmask[i];
}

void IPV4::ConfigureDhcp()
{
    m_bUsingDhcp = true;
    //!@todo Configure DHCP
}

uint16_t IPV4::Ping(byte* pIp, void (*HandleEchoResponse)(uint16_t nSequence))
{
    byte pPayload[32] = {8}; //Populate type=8 (echo request)
    memset(pPayload + 1, 0, 5); //Clear next 5 bytes (code, checksum, identifier)
    pPayload[6] = (byte)(m_nPingSequence >> 8); //Populate 16-bit sequence number
    pPayload[7] = (byte)(m_nPingSequence & 0xFF);
    for(byte i = 8; i < 32; ++i)
        pPayload[i] = i; //Populate payload with gash but disernable data (not actually used beyond checksum checking) - we use sequential numbers 8 - 31
    uint16_t nChecksum = ribanEthernetProtocol::CreateChecksum(pPayload, 32);
    pPayload[2] = nChecksum >> 8; //Populate checksum (which is calcuated on payload with checksum filed set to zero)
    pPayload[3] = nChecksum & 0xFF;
    m_pHandleEchoResponse = HandleEchoResponse; //Populate echo response event handler

    SendPacket(pPayload, sizeof(pPayload), IP_PROTOCOL_ICMP, pIp);

    return m_nPingSequence++; //Return this sequence number and increment for next ping
}

void IPV4::EnableIcmp(bool bEnable)
{
    m_bIcmpEnabled = bEnable;
}

bool IPV4::IsLocalIp(byte* pIp)
{
    return(0 == memcmp(pIp, m_pLocalIp, 4));
}

bool IPV4::IsOnLocalSubnet(byte* pIp)
{
    for(byte i = 0; i < 4; ++i)
        if((m_pSubnetIp[i] & pIp[i]) != m_pSubnetIp[i])
            return false;
    return true;
}

bool IPV4::IsBroadcast(byte* pIp)
{
    bool bReturn = true;
    for(byte i = 0; i < 4; ++i)
        bReturn &= (*(pIp + i) == 255);
    bReturn |= (0 == memcmp(pIp, m_pBroadcastIp, 4));
    return bReturn;
}

bool IPV4::IsMulticast(byte* pIp)
{
    return((*pIp & 0xE0) == 0xE0);
}

byte* IPV4::ArpLookup(byte* pIp, uint16_t nTimeout)
{
    byte pArpPacket[44] = {0x08,0x06,0x00,0x01,0x08,0x00,0x06,0x04,0x00,0x01}; //Populate Ethernet type, H/W type, Protocol type, H/W address len, Protocol address len, Operation
    memcpy(pArpPacket + 10, m_pLocalMac, 6);
    memcpy(pArpPacket + 16, m_pLocalIp, 4);
    memcpy(pArpPacket + 26, pIp, 4);
    byte pBroadcast[6] = {255,255,255,255,255,255};
    TxListEntry txListEntry(pArpPacket, 42);
    TxPacket(&txListEntry, pBroadcast);
    uint16_t nExpire = millis() + nTimeout; //Store expiry time
    while(nExpire > millis())
        Process(pArpPacket, 44); //!@todo use constant for ARP_PACKET_LEN - 1
    //!@todo get ARP to return
    //!@todo detect ARP response

    return NULL;
}

void IPV4::PrintIp(byte* pIp)
{
    Serial.print(*pIp);
    Serial.print(".");
    Serial.print(*(pIp + 1));
    Serial.print(".");
    Serial.print(*(pIp + 2));
    Serial.print(".");
    Serial.print(*(pIp + 3));
}
