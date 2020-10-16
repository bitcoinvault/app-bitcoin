#include "btchip_btcv3Keys.h"
#include "btchip_internal.h"

void generateScriptHash(unsigned char *hashBuffer, unsigned char *keyPath, unsigned char *chainCode)
{
    unsigned char scriptBuffer[201];
    unsigned int bufferTailIndex = 0;
    scriptBuffer[0] = 0x53; // OP_3
    
    btchip_private_derive_keypair(keyPath, 1, chainCode, Regular);
    scriptBuffer[1] = btchip_public_key_D.W_len;
    bufferTailIndex = 2;
    
    PRINTF("regular pubkey: %.*H\n", btchip_public_key_D.W_len, btchip_public_key_D.W);
    os_memmove(scriptBuffer + bufferTailIndex, btchip_public_key_D.W, btchip_public_key_D.W_len);
    bufferTailIndex += btchip_public_key_D.W_len;

    btchip_private_derive_keypair(keyPath, 1, chainCode, Instant);
    PRINTF("instant pubkey: %.*H\n", btchip_public_key_D.W_len, btchip_public_key_D.W);
    scriptBuffer[bufferTailIndex] = btchip_public_key_D.W_len;
    os_memmove(scriptBuffer + ++bufferTailIndex, btchip_public_key_D.W, btchip_public_key_D.W_len);
    bufferTailIndex += btchip_public_key_D.W_len;
    
    btchip_private_derive_keypair(keyPath, 1, chainCode, Recovery);
    PRINTF("recovery pubkey: %.*H\n", btchip_public_key_D.W_len, btchip_public_key_D.W);
    scriptBuffer[bufferTailIndex] = btchip_public_key_D.W_len;
    os_memmove(scriptBuffer + ++bufferTailIndex, btchip_public_key_D.W, btchip_public_key_D.W_len);
    bufferTailIndex += btchip_public_key_D.W_len;

    scriptBuffer[bufferTailIndex++] = 0x53; // OP_3
    scriptBuffer[bufferTailIndex] = 0xAE; // OP_CHECKMULTISIG
    PRINTF("scriptBuffer: %.*H\n", bufferTailIndex, scriptBuffer);

    btchip_public_key_hash160(scriptBuffer, 201, hashBuffer); // script hash, actually
    PRINTF("hashBuffer: %.*H\n", 20, hashBuffer);
}
