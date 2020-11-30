#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

unsigned short btchip_apdu_use_btcv_signature_password()
{
    unsigned char txType = G_io_apdu_buffer[ISO_OFFSET_P1];

    unsigned char passwordHash[32];

    cx_sha256_t shasha;
    cx_sha256_init(&shasha);
    if(BTCV_TX_TYPE_ALERT == txType)
    {
        btchip_context_D.transactionContext.btcvTxType = txType;
        return BTCHIP_SW_OK;
    }
    if(BTCV_TX_TYPE_INSTANT == txType)
    {
        cx_hash(&shasha.header, CX_LAST, &N_btchip.btcvInstantPassword, MAX_BTCV_PASSWORD_LEN , passwordHash, 32);
    }
    else if(BTCV_TX_TYPE_RECOVERY == txType)
    {
        cx_hash(&shasha.header, CX_LAST, &N_btchip.btcvRecoveryPassword, MAX_BTCV_PASSWORD_LEN , passwordHash, 32);
    }
    else
    {
        PRINTF("Unknown btcv tx type: %c\n", txType);
        return BTCHIP_SW_INCORRECT_DATA;
    }
    
    int cmpResult = memcmp(passwordHash, G_io_apdu_buffer + ISO_OFFSET_CDATA, MAX_BTCV_PASSWORD_LEN);

    if(0 != cmpResult)
    {
        PRINTF("BTCV password hashes not equal!\n");
        return BTCHIP_SW_INCORRECT_DATA;
    }

    btchip_context_D.transactionContext.btcvTxType = txType;
    return BTCHIP_SW_OK;
}
