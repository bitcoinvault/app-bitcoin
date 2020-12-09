#include "btchip_btcv3Keys.h"
#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

void insertPubkeyToBuffer(unsigned char *buffer, unsigned char *keyPath, unsigned char *chainCode, enum BtcvKeyType keyType, unsigned int *bufferTailIndex)
{
    btchip_private_derive_keypair(keyPath, 1, chainCode, keyType);
    PRINTF("pubkey (type %d):%.*H\n", keyType, btchip_public_key_D.W_len, btchip_public_key_D.W);
    buffer[(*bufferTailIndex)++] = btchip_public_key_D.W_len;
    os_memmove(buffer + *bufferTailIndex, btchip_public_key_D.W, btchip_public_key_D.W_len);
    *bufferTailIndex += btchip_public_key_D.W_len;
}

void generateMultiKeyScriptHash(unsigned char *hashBuffer, unsigned char *keyPath, unsigned char *chainCode)
{
    PRINTF("generateMultiKeyScriptHash\n");
    if(!isPasswordSet((void *)&N_btchip.btcvInstantPassword))
    {
        // OP_IF OP_1 OP_ELSE OP_2 OP_ENDIF
        unsigned char scriptBuffer[139] = {0x63, 0x51, 0x67, 0x52, 0x68};
        unsigned int bufferTailIndex = 5;

        // alert pubkey
        insertPubkeyToBuffer(scriptBuffer, keyPath, chainCode, Regular, &bufferTailIndex);
        // recovery pubkey
        insertPubkeyToBuffer(scriptBuffer, keyPath, chainCode, Recovery, &bufferTailIndex);

        scriptBuffer[bufferTailIndex++] = 0x52; // OP_2
        scriptBuffer[bufferTailIndex++] = 0xAE; // OP_CHECKMULTISIG
        PRINTF("2k scriptBuffer: %.*H\n", bufferTailIndex, scriptBuffer);
        PRINTF("2k bufferTailIndex: %d\n", bufferTailIndex);
        btchip_public_key_hash160(scriptBuffer, 139, hashBuffer); // script hash, actually
        PRINTF("2k hashBuffer: %.*H\n", 20, hashBuffer);
    }
    else
    {
        // OP_IF OP_1 OP_ELSE OP_IF OP_2 OP_ELSE OP_3 OP_ENDIF OP_ENDIF
        unsigned char scriptBuffer[209] = {0x63, 0x51, 0x67, 0x63, 0x52, 0x67, 0x53, 0x68, 0x68};
        unsigned int bufferTailIndex = 9;

        // alert pubkey
        insertPubkeyToBuffer(scriptBuffer, keyPath, chainCode, Regular, &bufferTailIndex);
        // instant pubkey
        insertPubkeyToBuffer(scriptBuffer, keyPath, chainCode, Instant, &bufferTailIndex);
        // recovery pubkey
        insertPubkeyToBuffer(scriptBuffer, keyPath, chainCode, Recovery, &bufferTailIndex);

        scriptBuffer[bufferTailIndex++] = 0x53; // OP_3
        scriptBuffer[bufferTailIndex++] = 0xAE; // OP_CHECKMULTISIG
        PRINTF("scriptBuffer: %.*H\n", bufferTailIndex, scriptBuffer);
        PRINTF("bufferTailIndex: %d\n", bufferTailIndex);

        btchip_public_key_hash160(scriptBuffer, 209, hashBuffer); // script hash, actually
        PRINTF("hashBuffer: %.*H\n", 20, hashBuffer);
    }
}
