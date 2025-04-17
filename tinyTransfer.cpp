//
// Created by dylan on 8/12/23.
//
#include <cstring>
#include <iostream>

#include "tinyTransfer.h"

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

TinyTransferUpdatePacket::TinyTransferUpdatePacket(uint8_t* _data, uint16_t _length, uint32_t _packetId, char* _log, uint16_t _logSize, bool compressed, bool isIntegrator) : TinyTransferUpdatePacket() {
    //Input data is compressed
    if (compressed) {
        //Initialize compression
        heatshrink_encoder_reset(&hs_encoder);
        size_t count = 0;
        size_t sunk = 0;
        size_t polled = 0;

        //Loop over all data
        while (sunk < _length) {
            
            //Feed data into encoder
            heatshrink_encoder_sink(&hs_encoder, &_data[sunk], _length - sunk, &count);
            sunk += count;

            //If reached end of data, finish
            if (sunk >= _length) {
                heatshrink_encoder_finish(&hs_encoder);
            }
            
            //Retrieve compressed data
            HSE_poll_res pres;
            do {
                pres = heatshrink_encoder_poll(&hs_encoder, &payload[polled], sizeof(TinyTransferUpdatePacket) - polled, &count);
                polled += count;
            } while (pres == HSER_POLL_MORE);

            //If all data processed, finish process
            if (sunk == _length) {
                heatshrink_encoder_finish(&hs_encoder);
            }
        }
        //How much compressed data there was
        payloadSize = (uint16_t)polled;

        //Set packet flag for compressed data
        packetFlags |= TINY_TRANSFER_UPDATE_FLAGS_COMPRESSED;
    }
    else {
        //Copy data into the payload
        memcpy(payload, _data, _length);

        //Length of payload is length of data
        payloadSize = _length;

        //Set packet for uncompresse data
        packetFlags &= ~TINY_TRANSFER_UPDATE_FLAGS_COMPRESSED;
    }

    // Copy log (only for hamster packets)
    if (!isIntegrator) {
        //Copy data into log
        memcpy(log, _log, _logSize);
        logSize = _logSize;
    }else{
        logSize = 0;
    }

    //Set packet flag for integrator packet
    if (isIntegrator) {
        packetFlags |= TINY_TRANSFER_UPDATE_FLAGS_INTEGRATOR_PACK;
    }
    
    //Update class with relevant input packet id and checksums
    packetId = _packetId;
    payloadChecksum = fletcher16(payload, payloadSize);
    headerChecksum = fletcher16(header, sizeof(header));
}

bool TinyTransferUpdatePacket::isValid() {
    bool sohCheck = startOfHeader == TINY_TRANSFER_UPDATE_SOH;
    bool headerPass = fletcher16(header, sizeof(header)) == headerChecksum;
    bool argsPass = fletcher16(payload, payloadSize) == payloadChecksum && payloadSize <= TINY_TRANSFER_UPDATE_MAX_PAYLOAD_LENGTH;

    return sohCheck && headerPass && argsPass;
}

uint16_t TinyTransferUpdatePacket::serialize(uint8_t* output) {
    memcpy(output, header, sizeof(header));
    //Header checksum
    memcpy(output + sizeof(header), &headerChecksum, sizeof(headerChecksum));
    //Payload 
    memcpy(output + sizeof(header) + sizeof(headerChecksum), payload, payloadSize);
    //Log
    memcpy(output + sizeof(header) + sizeof(headerChecksum) + payloadSize, log, logSize);

    return sizeof(header) + sizeof(headerChecksum) + payloadSize + logSize;
}

bool TinyTransferUpdatePacket::isCompressed() {
    return packetFlags & TINY_TRANSFER_UPDATE_FLAGS_COMPRESSED;
}

uint16_t TinyTransferUpdatePacket::decompressPayload(uint8_t* output) {
    if (isCompressed()) {
        //Decompression initialization
        size_t input_index = 0, output_index = 0;
        size_t input_size = 0, output_size = 0;
        HSD_poll_res poll_res;
        HSD_finish_res finish_res;

        heatshrink_decoder_reset(&hs_decoder);

        //Loop over all data
        while (input_index < payloadSize) {
            //Decompress data
            heatshrink_decoder_sink(&hs_decoder, &payload[input_index], payloadSize - input_index, &input_size);
            input_index += input_size;

            //Retrieve decompressed data
            do {
                poll_res = heatshrink_decoder_poll(&hs_decoder, &output[output_index], sizeof(payload) - output_index, &output_size);
                output_index += output_size;

            } while (poll_res == HSDR_POLL_MORE && output_index < payloadSize);
        }

        finish_res = heatshrink_decoder_finish(&hs_decoder);

        //Final data decompressing?
        while (finish_res == HSDR_FINISH_MORE) {
            finish_res = heatshrink_decoder_finish(&hs_decoder);
            do {
                poll_res = heatshrink_decoder_poll(&hs_decoder, &output[output_index], sizeof(payload) - output_index, &output_size);
                output_index += output_size;
            } while (poll_res == HSDR_POLL_MORE);
        }

        return (uint16_t)output_index;
    }
    else {
        //If data isn't compressed spit back out raw payload
        memcpy(output, payload, payloadSize);
        return payloadSize;
    }
}

TinyTransferUpdateParser::TinyTransferUpdateParser() {
    init();
}

void TinyTransferUpdateParser::init(){
    completedPacket = inputPacket;
    
    //First state is looking for start of header 
    state = TINY_TRANSFER_PARSER_SEARCHING_FOR_SOH;
    soh = 0;
    inputPacket = TinyTransferUpdatePacket();
    position = 0;
}

bool TinyTransferUpdateParser::processByte(uint8_t byte){
    //Searching for MDLN
    if(state == TINY_TRANSFER_PARSER_SEARCHING_FOR_SOH){
        //Read in another byte into soh
        soh = soh >> 8;
        soh |= (byte << 24);

        //If MDLN found (little endian)
        if(soh == TINY_TRANSFER_UPDATE_SOH){

            //Transition to next state
            state = TINY_TRANSFER_PARSER_HEADER;

            //Put MDLN into input packet header, move onto next data
            memcpy(inputPacket.header, &soh, sizeof(soh));
            position = sizeof(soh);
        }
    }

    //Search for rest of header
    else if (state == TINY_TRANSFER_PARSER_HEADER){
        //Input rest of header data into object members
        inputPacket.header[position] = byte;
        position++;

        if(position >= sizeof(TinyTransferUpdatePacket::header)){
            state = TINY_TRANSFER_PARSER_HEADER_CHECKSUM;
            position = 0;
        }
    }

    //Validate header 
    else if (state == TINY_TRANSFER_PARSER_HEADER_CHECKSUM){
        ((uint8_t*)(&inputPacket.headerChecksum))[position] = byte;
        position++;
        if(position == sizeof(inputPacket.headerChecksum)){
            uint16_t redo_checksum = fletcher16(inputPacket.header, sizeof(TinyTransferUpdatePacket::header));
            
            //If checksum of header matches header checksum in the array
            if(redo_checksum == inputPacket.headerChecksum){
                //Payload present - process it
                if(inputPacket.payloadSize != 0){

                    state = TINY_TRANSFER_PARSER_PAYLOAD;
                    position = 0;
                } //No payload but has log - skip to parse log
                else if((inputPacket.logSize != 0)){
                    state = TINY_TRANSFER_PARSER_LOG;
                    position = 0;
                }else{ //No log or payload - finish
                    init();
                    return true;
                }
            }

            //invalid checksum, start over again
            else {
                init();
            }
        }
    }

    //Read payload
    else if (state == TINY_TRANSFER_PARSER_PAYLOAD) {
        //Input payload into parser packet & move to the next byte
        inputPacket.payload[position] = byte;
        position++;

        //If reached the end of payload
        if(position >= inputPacket.payloadSize){
            //No log given, exit - valid
            if(inputPacket.logSize == 0){
                init();
                return true;
            }
            else{
                state = TINY_TRANSFER_PARSER_LOG;
                position = 0;
            }
        }
    }

    //Reading log
    else if (state == TINY_TRANSFER_PARSER_LOG){
        inputPacket.log[position] = byte;
        position++;
        
        //If finished reading log, exit
        if(position >= inputPacket.logSize){
            init();
            return true;
        }

    }
    return false;
}

TinyTransferRPCPacket::TinyTransferRPCPacket(uint8_t* _data) : TinyTransferRPCPacket() {
    //Header
    memcpy(header, _data, sizeof(header));
    //Header checksum
    memcpy(&headerChecksum, _data + sizeof(header), sizeof(headerChecksum));
    //Arguments
    uint16_t copyLength = procArgsLength > TINY_TRANSFER_RPC_MAX_ARGS_SIZE ? TINY_TRANSFER_RPC_MAX_ARGS_SIZE : procArgsLength;
    memcpy(args, _data + sizeof(header) + sizeof(headerChecksum), copyLength);
}

bool TinyTransferRPCPacket::isValid() {
    bool sohCheck = startOfHeader == TINY_TRANSFER_RPC_SOH;
    bool headerPass = fletcher16(header, sizeof(header)) == headerChecksum;
    bool argsPass = fletcher16(args, procArgsLength) == procArgsChecksum && procArgsLength <= TINY_TRANSFER_RPC_MAX_ARGS_SIZE;

    //return sohCheck && headerPass && argsPass;
    return headerPass;
}

TinyTransferRPCParser::TinyTransferRPCParser() {
    init();
}

void TinyTransferRPCParser::init(){
    completedPacket = inputPacket;

    //First state is looking for NMEI
    state = TINY_TRANSFER_PARSER_SEARCHING_FOR_SOH;
    soh = 0;
    inputPacket = TinyTransferRPCPacket();
    position = 0;
}

bool TinyTransferRPCParser::processByte(uint8_t byte){
    //Searching for NMEI
    if(state == TINY_TRANSFER_PARSER_SEARCHING_FOR_SOH){
        soh = soh >> 8;
        soh |= (byte << 24);
        
        //NMEI found
        if(soh == TINY_TRANSFER_RPC_SOH){
            state = TINY_TRANSFER_PARSER_HEADER;
            memcpy(inputPacket.header, &soh, sizeof(soh));
            position = sizeof(soh);
        }
    }

    //Search for rest of header
    else if (state == TINY_TRANSFER_PARSER_HEADER){
        inputPacket.header[position] = byte;
        position++;
        
        //Reached the end of the header
        if(position >= sizeof(TinyTransferRPCPacket::header)){
            state = TINY_TRANSFER_PARSER_HEADER_CHECKSUM;
            position = 0;
        }
    }

    //Validate header
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

    //Process payload
    else if (state == TINY_TRANSFER_PARSER_PAYLOAD) {
        inputPacket.args[position] = byte;
        position++;

        //Reached the end of the payload
        if(position >= inputPacket.procArgsLength){
            init();
            return true;
        }
    }
    return false;
}
