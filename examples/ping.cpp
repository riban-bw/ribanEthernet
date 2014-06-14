#include "Arduino.h"
#include "include/ipv4.h"

static const byte ETHERNET_CS_PIN = 10;

IPV4 g_ipv4;
byte pBuffer[100];
uint16_t nTimestamp;
uint16_t nPingSequence;

void HandleEchoResponse(uint16_t nSequence)
{
    nTimestamp = millis() - nTimestamp;
    Serial.print(F("Echo response - loop delay="));
    Serial.print(nTimestamp);
    Serial.print(F("ms - "));
    if(nPingSequence == nSequence)
        Serial.println("Corresponds to our ping");
    else
        Serial.println("Does not correspond to our ping");
}

/** Initialisation */
void setup()
{
    Serial.begin(9600);
    Serial.println(F("Ping example"));
    byte pMac[6] = {0x12,0x34,0x56,0x78,0x9A,0xBC};
    g_ipv4.begin(pMac);
    Serial.println(F("IPV4 interface started"));
    byte pIp[4] = {192,168,0,99};
    byte pGw[4] = {192,168,0,254};
    byte pNetmask[4] = {255,255,255,0};
    g_ipv4.ConfigureStaticIp(pIp, pGw, 0, pNetmask);
    nTimestamp = millis();
    byte pHost[4] = {192,168,0,6};
    nPingSequence = g_ipv4.Ping(pHost, HandleEchoResponse);
    Serial.print("IP Address = ");
    IPV4::PrintIp(pIp);
    Serial.println();
}


/** Main program loop */
void loop()
{
//    Serial.print(F("."));
    g_ipv4.Process(pBuffer, sizeof(pBuffer));
    if(Serial.available() > 0)
    {
        char cInput = Serial.read();
        switch(cInput)
        {
            case 'R':
                setup();
                break;
            case ' ':
                Serial.println(F("I'm Alive!"));
                break;
        }
    }
//    delay(1000);
}

