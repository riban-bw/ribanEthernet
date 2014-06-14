#include "ribanEthernet.h"
#include "ribanethernetprotocol.h"
#include <Arduino.h>

ribanEthernet::ribanEthernet(byte nChipSelectPin) :
    m_nChipSelectPin(nChipSelectPin)
{
    for(unsigned int nIndex = 0; nIndex < MAX_PROTOCOLS; ++nIndex)
        m_apProtocols[nIndex] = NULL; //clear list of protocols
    m_nProtocolQuant = 0; //Reset protocols
    m_pHandleTxError = NULL;
}

ribanEthernet::~ribanEthernet()
{
}

void ribanEthernet::begin(byte* pMac)
{
    memcpy(m_pLocalMac, pMac, 6); //copy MAC address
    m_nic.Initialize(pMac, m_nChipSelectPin);
    Init();
}

void ribanEthernet::Process(byte* pBuffer, uint16_t nSize)
{
    uint16_t nQuant = m_nic.PacketReceive(pBuffer, nSize);
    if(nQuant)
        Serial.print(".");

    if(nQuant > nSize)
    {
        Serial.print(F("Error - Rx data ("));
        Serial.print(nQuant);
        Serial.print(F(") too large for buffer("));
        Serial.print(nSize);
        Serial.println(")");
        return;
    }
    if(nQuant >= 14)
    {
        //Process recieved packet
        byte* pPos = pBuffer;
        memcpy(m_pRemoteMac, pPos + 6, 6);
        pPos += 12; //Set pointer at protocol type / data length
        nQuant -= 12;
        uint16_t nResult = DoProcess(pPos, nQuant);
        pPos += nResult;
        nQuant -= nResult;
        if(nQuant)
            //Iterate through defined protocols
            for(unsigned int nIndex = 0; nIndex < m_nProtocolQuant; ++nIndex)
                if(m_apProtocols[nIndex] && m_apProtocols[nIndex]->Process(pPos, nQuant))
                    break;
    }
    if(m_pHandleTxError && m_nic.TxGetStatus() == ENC28J60_TX_FAILED) //!@todo Get rid of chip specific code from Ethernet class
    {
        m_pHandleTxError();
        m_nic.TxClearError();
    }
}

bool ribanEthernet::AddProtocol(ribanEthernetProtocol* pProtocol)
{
    if(m_nProtocolQuant >= MAX_PROTOCOLS)
        return false;
    m_apProtocols[m_nProtocolQuant++] = pProtocol;
    return true;
}

void ribanEthernet::TxPacket(TxListEntry* pSendList, byte* pDestination)
{
    m_nic.TxBegin(); //Start Tx transaction
    if(pDestination)
        m_nic.TxAppend(pDestination, 6); //Use specified destination MAC
    else
        m_nic.TxAppend(m_pRemoteMac, 6); //Use last known remote host MAC
    m_nic.TxAppend(m_pLocalMac, 6); //Use our own MAC
    //Iterate through list of packet data buffers, appending to packet
    TxListEntry* pNext = pSendList;
    while(pNext)
    {
        m_nic.TxAppend(pNext->GetData(), pNext->GetLen());
        pNext = pNext->GetNext();
    }
    m_nic.TxEnd(); //End Tx transaction and send the packet
}

void ribanEthernet::SetTxErrorHandler(void (*HandleTxError)())
{
    m_pHandleTxError = HandleTxError;
}
