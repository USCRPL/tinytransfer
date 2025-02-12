//
// Created by dylan on 8/12/23.
//
#include <cstring>

#include "tinyTransfer.h"

extern "C" {
    #include "heatshrink_encoder.h"
}

/** Static compression encoder and decoder */
static heatshrink_encoder hs_encoder;

uint16_t fletcher16(const uint8_t* data, uint64_t length){
    uint32_t c0, c1;

    /*  Found by solving for c1 overflow: */
    /* n > 0 and n * (n+1) / 2 * (2^8-1) < (2^32-1). */
    for (c0 = c1 = 0; length > 0; ) {
        uint64_t blocklen = length;
        if (blocklen > 5802) {
            blocklen = 5802;
        }
        length -= blocklen;
        do {
            c0 = c0 + *data++;
            c1 = c1 + c0;
        } while (--blocklen);
        c0 = c0 % 255;
        c1 = c1 % 255;
    }
    return (c1 << 8 | c0);
}

TinyTransferUpdatePacket::TinyTransferUpdatePacket(uint8_t* _data, uint16_t _length, uint32_t _packetId, char* _log, uint16_t _logSize, bool compressed, bool isIntegrator) {
    packetFlags = 0;
    
    if (compressed) {
        heatshrink_encoder_reset(&hs_encoder);

        size_t count = 0;
        uint32_t sunk = 0;
        uint32_t polled = 0;

        while (sunk < _length) {
            heatshrink_encoder_sink(&hs_encoder, &_data[sunk], _length - sunk, &count);
            sunk += count;

            if (sunk >= _length) {
                heatshrink_encoder_finish(&hs_encoder);
            }

            HSE_poll_res pres;
            do {
                pres = heatshrink_encoder_poll(&hs_encoder, &payload[polled], sizeof(TinyTransferUpdatePacket) - polled, &count);
                polled += count;
            } while (pres == HSER_POLL_MORE);

            if (sunk == _length) {
                heatshrink_encoder_finish(&hs_encoder);
            }
        }

        payloadSize = polled;
        packetFlags |= TINY_TRANSFER_UPDATE_FLAGS_COMPRESSED;
    }
    else {
        memcpy(payload, _data, _length);
        payloadSize = _length;
        packetFlags &= ~TINY_TRANSFER_UPDATE_FLAGS_COMPRESSED;
    }

    // Copy log (only for hamster packets)
    if (!isIntegrator) {
        memcpy(log, _log, _logSize);
        logSize = _logSize;
    } else {
        logSize = 0;
    }

    if (isIntegrator) {
        packetFlags |= TINY_TRANSFER_UPDATE_FLAGS_INTEGRATOR_PACK;
    }
    
    packetId = _packetId;
    
    payloadChecksum = fletcher16(payload, payloadSize);
    headerChecksum = fletcher16(header, sizeof(header));
}

uint16_t TinyTransferUpdatePacket::TinyTransferUpdatePacket::serialize(uint8_t* output) {
    memcpy(output, header, sizeof(header));
    memcpy(output + sizeof(header), &headerChecksum, sizeof(headerChecksum));
    memcpy(output + sizeof(header) + sizeof(headerChecksum), payload, payloadSize);
    memcpy(output + sizeof(header) + sizeof(headerChecksum) + payloadSize, log, logSize);

    return sizeof(header) + sizeof(headerChecksum) + payloadSize + logSize;
}


TinyTransferUpdateParser::TinyTransferUpdateParser() {
    init();
}

void TinyTransferUpdateParser::init(){
    completedPacket = inputPacket;
    state = TINY_TRANSFER_PARSER_SEARCHING_FOR_SOH;
    soh = 0;
    inputPacket = TinyTransferUpdatePacket();
    position = 0;
}

bool TinyTransferUpdateParser::processByte(uint8_t byte){
    if(state == TINY_TRANSFER_PARSER_SEARCHING_FOR_SOH){
        soh = soh >> 8;
        soh |= (byte << 24);

        if(soh == TINY_TRANSFER_UPDATE_SOH){
            state = TINY_TRANSFER_PARSER_HEADER;
            memcpy(inputPacket.header, &soh, sizeof(soh));
            position = sizeof(soh);
        }
    }

    else if (state == TINY_TRANSFER_PARSER_HEADER){
        inputPacket.header[position] = byte;
        position++;

        if(position >= sizeof(TinyTransferUpdatePacket::header)){
            state = TINY_TRANSFER_PARSER_HEADER_CHECKSUM;
            position = 0;
        }
    }

    else if (state == TINY_TRANSFER_PARSER_HEADER_CHECKSUM){
        ((uint8_t*)(&inputPacket.headerChecksum))[position] = byte;
        position++;
        if(position == sizeof(inputPacket.headerChecksum)){
            uint16_t redo_checksum = fletcher16(inputPacket.header, sizeof(TinyTransferRPCPacket::header));

            if(redo_checksum == inputPacket.headerChecksum){
                if (inputPacket.payloadSize == 0) {
                    init();
                    return true;
                }

                state = TINY_TRANSFER_PARSER_PAYLOAD;
                position = 0;
            }
            else {
                init();
            }
        }
    }

    else if (state == TINY_TRANSFER_PARSER_PAYLOAD) {
        inputPacket.payload[position] = byte;

        if(position >= inputPacket.payloadSize){
            ///send packet or something or return true
            init();
            return true;
        }

        position++;
    }
    return false;
}


TinyTransferRPCPacket::TinyTransferRPCPacket() {

}

TinyTransferRPCPacket::TinyTransferRPCPacket(uint8_t* _data) {
    memcpy(header, _data, sizeof(header));
    memcpy(&headerChecksum, _data + sizeof(header), sizeof(headerChecksum));
    uint16_t copyLength = procArgsLength > TINY_TRANSFER_RPC_MAX_ARGS_SIZE ? TINY_TRANSFER_RPC_MAX_ARGS_SIZE : procArgsLength;
    memcpy(args, _data + sizeof(header) + sizeof(headerChecksum), copyLength);
}

bool TinyTransferRPCPacket::isValid() {
    bool sohCheck = startOfHeader == TINY_TRANSFER_RPC_SOH;
    bool headerPass = fletcher16(header, sizeof(header)) == headerChecksum;
    bool argsPass = fletcher16(args, procArgsLength) == procArgsChecksum && procArgsLength <= TINY_TRANSFER_RPC_MAX_ARGS_SIZE;

    return sohCheck && headerPass && argsPass;
}

TinyTransferRPCParser::TinyTransferRPCParser() {
    init();
}

void TinyTransferRPCParser::init(){
    completedPacket = inputPacket;
    state = TINY_TRANSFER_PARSER_SEARCHING_FOR_SOH;
    soh = 0;
    inputPacket = TinyTransferRPCPacket();
    position = 0;
}

bool TinyTransferRPCParser::processByte(uint8_t byte){
    if(state == TINY_TRANSFER_PARSER_SEARCHING_FOR_SOH){
        soh = soh >> 8;
        soh |= (byte << 24);

        if(soh == TINY_TRANSFER_RPC_SOH){
            state = TINY_TRANSFER_PARSER_HEADER;
            memcpy(inputPacket.header, &soh, sizeof(soh));
            position = sizeof(soh);
        }
    }

    else if (state == TINY_TRANSFER_PARSER_HEADER){
        inputPacket.header[position] = byte;
        position++;

        if(position >= sizeof(TinyTransferRPCPacket::header)){
            state = TINY_TRANSFER_PARSER_HEADER_CHECKSUM;
            position = 0;
        }
    }

    else if (state == TINY_TRANSFER_PARSER_HEADER_CHECKSUM){
        ((uint8_t*)(&inputPacket.headerChecksum))[position] = byte;
        position++;
        if(position == sizeof(inputPacket.headerChecksum)){
            uint16_t redo_checksum = fletcher16(inputPacket.header, sizeof(TinyTransferRPCPacket::header));

            if(redo_checksum == inputPacket.headerChecksum){
                if (inputPacket.procArgsLength == 0) {
                    init();
                    return true;
                }

                state = TINY_TRANSFER_PARSER_PAYLOAD;
                position = 0;
            }
            else {
                init();
            }
        }
    }

    else if (state == TINY_TRANSFER_PARSER_PAYLOAD) {
        inputPacket.args[position] = byte;

        if(position >= inputPacket.procArgsLength){
            ///send packet or something or return true
            init();
            return true;
        }

        position++;
    }
    return false;
}
