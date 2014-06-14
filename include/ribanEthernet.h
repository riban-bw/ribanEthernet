/**     ribanEthernet - Extensible Ethernet interface
*       Copyright (c) 2014, Brian Walton. All rights reserved. GLPL.
*       Source availble at https://github.com/riban-bw/ribanEthernet.git
*       Allows use of different network interface controllers (not yet!)
*       Allows different protocols to be added
*
*       Proposed protocols:
*           Raw Ethernet Type II (done)
*           IPV4 (done) (and IPV6)
*               ARP (done)
*               ICMP
*               DHCP
*               DNS
*               UDP
*                  (S)NTP
*                   SNMP
*               TCP
*                   HTTP
*                   TELNET
*               SMTP
*               FTP
*
*       Uses instant of a network interface chip driver (m_nic). Each NIC driver must implemnent public functions:
*           initialize
*           packetReceive
*           getTxStatus
*           ClearTxError
*           TxBegin
*           TxAppend
*           TxEnd
*       Currently implemented NICs:
*           ENC28J60
*/

#pragma once
#include <Arduino.h>
#include "enc28j60.h" //!@todo Abstract NIC

class ribanEthernetProtocol;
class TxListEntry;

const static unsigned int MAX_PROTOCOLS = 16; //!@todo make protocols a linked list?

/** @brief  This class provides an Ethernet interface
*/
class ribanEthernet
{
    public:
        /** @brief  Construct an interface
        *   @param  nChipSelectPin Arduino pin number used as chip select. Default = 10.
        */
        ribanEthernet(byte nChipSelectPin = 10);

        virtual ~ribanEthernet();

        /** @brief  Initialise interface
        *   @param  pMac Pointer to MAC hardware address
        */
        void begin(byte* pMac);

        /** @brief  Initialise class
        *   @note   Pure virtual function must be implemented in derived class
        *   @note   Use to initialise derived classes
        */
        virtual void Init() = 0;

        /** @brief  Process recieved data and send any pending data
        *   @param  pBuffer Pointer to data buffer to populate
        *   @param  nSize Maximum number of bytes to read (size of pData buffer)
        */
        void Process(byte* pBuffer, uint16_t nSize);

        /** @brief  Adds a protocol handler
        *   @param  pProtocol Pointer to an instance of the protocol to add
        *   @return <i>bool</i> True on success
        *   @note   Protocol is a class derived from ribanEthernetProtocol which handles a particular network protocol
        */
        bool AddProtocol(ribanEthernetProtocol* pProtocol);

        /** @brief  Set the handler function for transmission errors
        *   @param  TxErrorHandler Pointer to error handler function
        *   @note   Error handler function should be declared: void HandleTxError();
        */
        void SetTxErrorHandler(void (*HandleTxError)());

        byte* GetMac() { return m_pLocalMac; };

    protected:
        /** @brief  Send data packet
        *   @param  pData Pointer to data buffer
        *   @param  pLen Quanity of bytes to send
        *   @param  pDestination Pointer to destination address. Use last recieved remote host if NULL. Default = NULL
        */
        void TxPacket(TxListEntry* pSendList, byte* pDestination = NULL);

        //!@todo Allow alternate NIC chips, e.g. W5100
        #ifdef NIC_W5100
        W5100 m_nic //!< Instance of network interface device
        #else
        ENC28J60 m_nic; //!< Instance of network interface device
        #endif // W5100
        byte m_pLocalMac[6]; //!< Pointer to local host hardware MAC address
        byte m_pRemoteMac[6]; //!< Pointer to remote host hardware MAC address

    private:

        /** @brief  Process derived classes
        *   @param  pBuffer Pointer to data buffer
        *   @param  nLen Quantity of data bytes in buffer
        *   @return <i>unsigned int<i> Quantity of bytes consumed by this protocol. Return 0 if protocol does not handle data in buffer.
        *   @note   Must consume all expected data, e.g. return value should include any padding.
        *   @note   If packet must be sent after processing, populate buffer with data and set m_nSendPacketLen with size of Ethernet payload
        *   @note   This pure virtual function must be overriden in derived classes to handle incoming Ethernet payload data
        *   @todo   Should pBuffer be const?
        */
        virtual uint16_t DoProcess(byte* pBuffer, uint16_t nLen) = 0;

        byte m_nChipSelectPin; //!< Index of pin used to select NIC
        unsigned int m_nProtocolQuant; //!< Quantity of protocols monitored
        ribanEthernetProtocol* m_apProtocols[MAX_PROTOCOLS]; //!< List of protocol handlers
        void (*m_pHandleTxError)(); //!< Pointer to function to handle Tx error
};
