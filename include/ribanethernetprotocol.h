#pragma once

#include <Arduino.h>
#include "txlistentry.h"

/** Template class for protocols
*   Must implement Process() function
*/
class ribanEthernetProtocol
{
    public:
        ribanEthernetProtocol(ribanEthernetProtocol* pParent = NULL);
        virtual ~ribanEthernetProtocol();

        /** @brief  Initialise protocol
        *   @note   Virtual function may be overriden to provide initialisation
        */
        virtual void Init();

        /** @brief  Process data buffer
        *   @param  pBuffer Pointer to data buffer
        *   @param  nLen Quantity of data bytes in buffer
        *   @return <i>unsigned int<i> Quantity of bytes consumed by this protocol. Return 0 if protocol does not handle data in buffer.
        *   @note   Must consume all expected data, e.g. return value should include any padding.
        *   @note   If packet must be sent after processing, populate buffer with data and set m_nSendPacketLen with size of Ethernet payload
        *   @note   Override this function to handle incoming Ethernet data
        *   @todo   Should pBuffer be const?
        */
        virtual uint16_t Process(byte* pBuffer, uint16_t nLen);

        /** @brief  Create a checksum
        *   @param  pData Pointer to data
        *   @param  nLen Quantity of bytes
        *   @return <i>uint16_t</i> Checksum value
        *   @note   Static function allows calling without object and is used by higher level protocols, e.g. IPv4
        *   @note   Passing data segment (including embedded checksum) will return zero if checksum is valid
        */
        static uint16_t CreateChecksum(byte* pData, uint16_t nLen);

        /** @brief  Check if packet pending to be sent
        *   @return <i>uint16_t</i> Quantity of bytes to send. 0 if no packet pending
        */
        uint16_t GetPendingSend();

        /** @brief  Send packet
        *   @param  pData Pointer to data payload
        *   @param  nLen Quantity of bytes in data payload
        *   @param  pDestination Pointer to destination address, e.g. 4 bytes for IPv4
        */
        virtual void SendPacket(byte* pData, uint16_t nLen, byte* pDestination = NULL);

        /** @brief  Cascades packet payload up protocol hierarchy
        *   @param  pList Pointer to protocol list
        *   @note   Overrid this function to handle sending data by creating a TxListEntry with protocol header
        *   @note   May need to add several elements to send data list, e.g. header, payload, checksum.
        */
        virtual void CascadeProtocol(TxListEntry* pList);

    protected:
        uint16_t m_nSendPacketLen; //!< Size of packet to send. 0 if no packet pending
        ribanEthernetProtocol* m_pParent; //!< Pointer to the parent protocol, e.g. ICMP class would point to IP instance

    private:

};

