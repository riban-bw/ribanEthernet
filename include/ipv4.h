/**     IPV4 provides IPv4 class derived from ribanEthernet
*       Copyright (c) 2014, Brian Walton. All rights reserved. GLPL.
*       Source availble at https://github.com/riban-bw/ribanEthernet.git
*
*       Allows different protocols to be added
*/

#pragma once

#include "ribanEthernet.h"
#include "ribanethernetprotocol.h"

const static uint16_t IPV4_HEADER_SIZE = 20;
const static uint16_t IPV4_MINLEN = 26;
const static uint16_t IPV4_SOURCE_IP_OFFSET = 12;
const static uint16_t IPV4_DESTINATION_IP_OFFSET = 16;
const static uint16_t IPV4_CHECKSUM_OFFSET = 10;

const static uint16_t IP_PROTOCOL_ICMP  = 1;
const static uint16_t IP_PROTOCOL_IGMP  = 2;
const static uint16_t IP_PROTOCOL_TCP   = 6;
const static uint16_t IP_PROTOCOL_UDP   = 17;
const static uint16_t IP_PROTOCOL_ENCAP = 41;
const static uint16_t IP_PROTOCOL_OSPF  = 89;
const static uint16_t IP_PROTOCOL_SCTP  = 132;

const static unsigned int ARP_GATEWAY_INDEX = 0;
const static unsigned int ARP_DNS_INDEX = 1;

const static uint16_t ICMP_HEADER_SIZE = 8;
const static byte ICMP_TYPE_ECHOREPLY = 0;
const static byte ICMP_TYPE_ECHOREQUEST = 8;
const static uint16_t ICMP_CHECKSUM_OFFSET = 2;

class ArpEntry
{
    public:
        ArpEntry()
        {
            //Reset IP and MAC addresses to all zeros
            for(int i = 0; i < 4; ++i)
                ip[i] = 0;
            for(int i = 0; i < 6; ++i)
                mac[i] = 0;
        };
        byte ip[4];
        byte mac[6];
};

class IPV4 : public ribanEthernet
{
    public:
        /** @brief  Initialise class
        */
        void Init();

        /** @brief  Configure network interface with static IP
        *   @param  pIp Pointer to IP address (4 bytes). 0 for no change.
        *   @param  pGw Pointer to gateway address (4 bytes). 0 for no change. Default = 0
        *   @param  pDns Pointer to DNS address (4 bytes). 0 for no change. Default = 0
        *   @param  pNetmask Pointer to subnet mask (4 bytes). 0 for no change. Default = 0
        *   @return <i>bool</i> Returns true on success - actually always true
        */
        void ConfigureStaticIp(const uint8_t* pIp,
                            const uint8_t* pGw = 0,
                            const uint8_t* pDns = 0,
                            const uint8_t* pNetmask = 0);

        /** @brief  Configure network interface with DHCP
        */
        void ConfigureDhcp();

        /** @brief  Send packet
        *   @param  pTxListEntry Pointer to the top-level list entry describing the IP payload
        *   @param  nProtocol IP protocol number, e.g. ICMP=1
        *   @param  pDestination Pointer to destination address, e.g. 4 bytes for IPv4
        */
        void SendPacket(TxListEntry* pTxListEntry, byte nProtocol, byte* pDestination = NULL);

        /** @brief  Send packet
        *   @param  pData Pointer to the IP payload
        *   @param  nLen Quantity of bytes in payload
        *   @param  nProtocol IP protocol number, e.g. ICMP=1
        *   @param  pDestination Pointer to destination address, e.g. 4 bytes for IPv4
        */
        void SendPacket(byte* pData, uint16_t nLen, byte nProtocol, byte* pDestination = NULL);

        /** @brief  Send an echo request (ping)
        *   @param  pIp Pointer to remote host IP
        *   @param  pHandler Pointer to handler function
        *   @return <i>uint16_t</i> Sequence number of this ping (may be used to match response)
        *   @note   Handler function is called when an echo response is recieved
        *   @note   Only one echo response handler function may be defined. Redefining will result in all responses being handled by newly defined function
        *   @note   Handler function should be declared: void HandleEchoResponse(uint16_t nSequence); where nSequence is the echo response sequence number
        *   @todo   Add ping parameters, e.g. quantity of pings, response handler, etc.
        */
        uint16_t Ping(byte* pIp, void (*HandleEchoResponse)(uint16_t nSequence));

        /** @brief  Enable / disable ICMP (ping) responses
        *   @param  bEnable True to enable, false to disable
        */
        void EnableIcmp(bool bEnable);


        /** @brief  Perform ARP request and update ARP cache table
        *   @param  pIp Pointer to IP address
        *   @param  nTimeout Quantity of milliseconds to wait for ARP response before abandoning ARP request as failed
        *   @return <i>byte*</i> Pointer to resulting MAC address or NULL on failure (timeout)
        *   @note   Blocks program flow whilst waiting for ARP response. All recieved packets are lost.
        */
        byte* ArpLookup(byte* pIp, uint16_t nTimeout = 500);

        /** @brief  Print IP address
        *   @param  pIp Pointer to IP address
        */
        static void PrintIp(byte* pIp);

        byte* GetIp() { return m_pLocalIp; };
        byte* GetGw() { return m_aArpTable[ARP_GATEWAY_INDEX].ip; };
        byte* GetDns() { return m_aArpTable[ARP_DNS_INDEX].ip; };
        byte* GetNetmask() { return m_pNetmask; };
        byte* GetBroadcastIp() { return m_pBroadcastIp; };
        bool IsUsingDhcp() { return m_bUsingDhcp; };

    protected:

    private:
        /** @brief  Process data buffer
        *   @param  pBuffer Pointer to data buffer
        *   @param  nLen Quantity of data bytes in buffer
        *   @return <i>unsigned int<i> Quantity of bytes consumed by this protocol. Return 0 if protocol does not handle data in buffer.
        *   @note   Must consume all expected data, e.g. return value should include any padding.
        *   @note   If packet must be sent after processing, populate buffer with data and set m_nSendPacketLen with size of Ethernet payload
        *   @note   Override this function to handle incoming Ethernet data
        *   @todo   Should pBuffer be const?
        */
        uint16_t DoProcess(byte* pBuffer, uint16_t nLen);

        /** @brief  Check for ICMP and process
        *   @param  pData Pointer to packet data payload
        *   @param  nLen Quantity of bytes in payload
        *   @return <i>bool</i> True if ICMP packet processed
        */
        bool ProcessIcmp(byte* pData, uint16_t nLen);

        /** @brief  Checks whether IP address is same as local host IP address
        *   @param  pIp IP address to check
        *   @return <i>bool</i> True if same
        */
        bool IsLocalIp(byte* pIp);

        /** @brief  Checks whether IP address is on local subnet or whether a gatway is required to reach host
        *   @param  pIp IP address to check
        *   @return <i>bool</i> True if on local subnet
        */
        bool IsOnLocalSubnet(byte* pIp);

        /** @brief  Check whether IP address is a broadcast address (subnet or global)
        *   @param  pIp Pointer to IP address
        *   @return <i>bool</i> True if a broadcast address
        */
        bool IsBroadcast(byte* pIp);

        /** @brief  Check whether IP address is a multicast address
        *   @param  pIp Pointer to IP address
        *   @return <i>bool</i> True if a multicast address
        */
        bool IsMulticast(byte* pIp);

        bool m_bUsingDhcp; //!< True if using DHCP. False if static IP configuration.
        bool m_bIcmpEnabled; //!< True to enable ICMP responses
        byte m_pLocalIp[4]; //!< IP address of remote host
        byte m_pRemoteIp[4]; //!< IP address of target (should be our IP, multicast or broadcast)
        byte m_pGwIp[4]; //!< Pointer to gateway / router IP address
        byte m_pDnsIp[4]; //!< Pointer to DNS IP address
        byte m_pNetmask[4]; //!< Pointer to netmask
        byte m_pSubnetIp[4]; //!< Pointer to the subnet address
        byte m_pBroadcastIp[4]; //!< Pointer to broadcast address

        byte m_nArpCursor; //!< Cursor holds index of next ARP table entry to update
        byte m_nIpv4Protocol; //!< IPv4 protocol of current message
        uint16_t m_nPingSequence; //!< ICMP echo response sequence number
        uint16_t m_nIdentification; //!< IPv4 packet identification
        uint16_t m_nIpv4Port; //!< IPv4 port number

        #ifndef ARP_TABLE_SIZE
            #define ARP_TABLE_SIZE 2
        #endif // ARP_TABLE_SIZE
        ArpEntry m_aArpTable[ARP_TABLE_SIZE + 2]; //!< ARP table. Minimum size is 2 to hold gateway and DNS host IP/MAC
        void (*m_pHandleEchoResponse)(uint16_t nSequence); //!< Pointer to function to handle echo response (pong)

};

