#pragma once
#include <Arduino.h>

class TxListEntry
{
    public:
        /** @brief  Construct an instance of a transmission list entry
        *   @param  pData Pointer to the data
        *   @param  nLen Quantity of bytes in data buffer
        *   @param  pNext Pointer to the next list entry. NULL if last entry in list. Default = NULL
        */
        TxListEntry(byte* pData, uint16_t nLen, TxListEntry* pNext = NULL);

        /** @brief  Get data
        *   @return <i>byte*</i> Pointer to the data
        */
        byte* GetData();

        /** @brief  Get size of data
        *   @return <i>uint16_t</i> Quantity of bytes in data
        */
        uint16_t GetLen();

        /** @brief  Get the next entry in the list
        *   @return <TxListEntry</i> Pointer to next entry. NULL if last entry
        */
        TxListEntry* GetNext();

    private:
        byte* m_pData; //!< Pointer to data buffer
        uint16_t m_nLen; //!< Quantity of bytes in data buffer
        TxListEntry* m_pNext = NULL; //!< Pointer to next list element - NULL if end of list
};
