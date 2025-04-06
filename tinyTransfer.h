//
// Created by dylan on 8/12/23.
//

#ifndef NEWHAMSTER_TINYTRANSFER_H
#define NEWHAMSTER_TINYTRANSFER_H

#define TINY_TRANSFER_UPDATE_SOH                   0x4E4C444D
#define TINY_TRANSFER_UPDATE_MAX_PAYLOAD_LENGTH    1024
#define TINY_TRANSFER_UPDATE_MAX_LOG_LENGTH        1024
#define TINY_TRANSFER_RPC_SOH                      0x49454D4E
#define TINY_TRANSFER_RPC_MAX_ARGS_SIZE            1024
#define TINY_TRANSFER_UPDATE_FLAGS_COMPRESSED      0x01
#define TINY_TRANSFER_UPDATE_FLAGS_INTEGRATOR_PACK 0x02

#include <initializer_list>
#include <cstdint>

extern "C" {
    #include "heatshrink_encoder.h"
    #include "heatshrink_decoder.h"
}

static heatshrink_encoder hs_encoder;
static heatshrink_decoder hs_decoder;

/**
 * This is a file for packaging data into packets for transfer over radio / written into FlashLog
 * This will grab a serialized data, adding headers and checksums to it
 */

/** Checksum algorithm fletcher-16, produces a 2 byte checksum */
uint16_t fletcher16(const uint8_t* data, uint64_t length);

/** Tiny Transfer Update Packet Structure
Header:
    0x00:   0x4D 0x44 0x4C 0x4E     // Start of Header (SOH)
    0x04:   uint32_t                // Message ID
    0x08:   uint16_t                // Packet flags
    0x0A:   uint16_t                // Payload size (bytes)
    0x0C:   uint16_t                // Payload checksum (fletcher16)

    0x0E:   uint16_t                // Header Checksum (fletcher16)

Payload:
    0x10:   uint8_t*                // Heatshrink compressed cache struct
*/

struct TinyTransferUpdatePacket {
    public:
        union {
            struct {
                uint32_t startOfHeader;
                uint32_t packetId;
                uint16_t packetFlags;
                uint16_t payloadSize;
                uint16_t payloadChecksum;
                uint16_t logSize;
            };

            struct {
                uint8_t header[16];
            };
        };

        uint16_t headerChecksum;
        uint8_t payload[TINY_TRANSFER_UPDATE_MAX_PAYLOAD_LENGTH] = {0};
        uint8_t log[TINY_TRANSFER_UPDATE_MAX_LOG_LENGTH] = {0};

        TinyTransferUpdatePacket(uint8_t* payload, uint16_t payloadSize, uint32_t packetId, char* log = NULL, uint16_t logSize = 0, bool compressed = true, bool isIntegrator = false);

        TinyTransferUpdatePacket() {
            startOfHeader = TINY_TRANSFER_UPDATE_SOH;
            packetId = 0;
            packetFlags = 0;
            payloadSize = 0;
            payloadChecksum = 0;
            headerChecksum = 0;
            logSize = 0;
        };

        bool isValid();

        uint16_t serialize(uint8_t* output);

        bool isCompressed();

        uint16_t decompressPayload(uint8_t* output);
};

/** Tiny Transfer RPC Packet Structure
Header:
    0x00:   0x4E 0x4D 0x45 0x49     // Start of Header (SOH)
    0x04:   uint32_t                // Packet nonce
    0x08:   uint16_t                // Procedure ID
    0x0A:   uint16_t                // Args size (bytes)
    0x0C:   uint16_t                // Args checksum (fletcher16)

    0x0E:   uint16_t                // Header Checksum (fletcher16)

Payload:
    0x10:   uint8_t*                // Heatshrink compressed args struct
*/

struct TinyTransferRPCPacket {
    public:
        union {
            struct {
                uint32_t startOfHeader;
                uint32_t packetNonce;
                uint16_t procId;
                uint16_t procArgsLength;
                uint16_t procArgsChecksum;
            };

            struct {
                uint8_t header[14];
            };
        };

        uint16_t headerChecksum;
        uint8_t args[TINY_TRANSFER_RPC_MAX_ARGS_SIZE] = {0};

        TinyTransferRPCPacket(uint8_t* _data); // deserealize

        TinyTransferRPCPacket() {
            startOfHeader = TINY_TRANSFER_RPC_SOH;
            packetNonce = 0;
            procId = 0;
            procArgsLength = 0;
            procArgsChecksum = 0;
            headerChecksum = 0;
        };

        bool isValid();
};

#define TINY_TRANSFER_PARSER_SEARCHING_FOR_SOH 0
#define TINY_TRANSFER_PARSER_HEADER 1
#define TINY_TRANSFER_PARSER_HEADER_CHECKSUM 2
#define TINY_TRANSFER_PARSER_PAYLOAD 3

struct TinyTransferUpdateParser {
    TinyTransferUpdateParser();
    void init();
    bool processByte(uint8_t);

    int state;  
    uint32_t soh;
    TinyTransferUpdatePacket inputPacket;
    TinyTransferUpdatePacket completedPacket;
    size_t position;
};

struct TinyTransferRPCParser {
    TinyTransferRPCParser();
    void init();
    bool processByte(uint8_t);

    int state;  
    uint32_t soh;
    TinyTransferRPCPacket inputPacket;
    TinyTransferRPCPacket completedPacket;
    size_t position;
};


#endif //NEWHAMSTER_TINYTRANSFER_H
