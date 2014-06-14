#include "txlistentry.h"

TxListEntry::TxListEntry(byte* pData, uint16_t nLen, TxListEntry* pNext) :
    m_pData(pData),
    m_nLen(nLen),
    m_pNext(pNext)
{
}

byte* TxListEntry::GetData()
{
    return m_pData;
}

uint16_t TxListEntry::GetLen()
{
    return m_nLen;
}

TxListEntry* TxListEntry::GetNext()
{
    return m_pNext;
}
