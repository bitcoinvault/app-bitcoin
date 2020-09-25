#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

#define PASSWORD_TYPE_INSTANT 0x00
#define PASSWORD_TYPE_RECOVERY 0x01

unsigned short btchip_apdu_set_btcv_password()
{
    PRINTF("btchip_apdu_set_btcv_password\n");
    PRINTF("btcvInstantPassword:\n%.*H\n", MAX_BTCV_PASSWORD_LEN, N_btchip.btcvInstantPassword);
    PRINTF("btcvRecoveryPassword:\n%.*H\n", MAX_BTCV_PASSWORD_LEN, N_btchip.btcvRecoveryPassword);
    unsigned char passwordType = G_io_apdu_buffer[ISO_OFFSET_P1];
    PRINTF("passwordType %c\n", passwordType);
    if(PASSWORD_TYPE_INSTANT == passwordType)
    	nvm_write((void *)&N_btchip.btcvInstantPassword, G_io_apdu_buffer + ISO_OFFSET_CDATA, G_io_apdu_buffer[ISO_OFFSET_LC]);
    if(PASSWORD_TYPE_RECOVERY == passwordType)
    	nvm_write((void *)&N_btchip.btcvRecoveryPassword, G_io_apdu_buffer + ISO_OFFSET_CDATA, G_io_apdu_buffer[ISO_OFFSET_LC]);
    PRINTF("btcvInstantPassword:\n%.*H\n", MAX_BTCV_PASSWORD_LEN, N_btchip.btcvInstantPassword);
    PRINTF("btcvRecoveryPassword:\n%.*H\n", MAX_BTCV_PASSWORD_LEN, N_btchip.btcvRecoveryPassword);
    return BTCHIP_SW_OK;
}
