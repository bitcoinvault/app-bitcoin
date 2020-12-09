#include "btchip_internal.h"
#include "btchip_apdu_constants.h"

bool shouldResetPassword()
{
    return G_io_apdu_buffer[ISO_OFFSET_LC] == 1 && G_io_apdu_buffer[0] == 0x00;
}

bool isPasswordSet(char *buf)
{
    PRINTF("isPasswordSet: %.*H\n",MAX_BTCV_PASSWORD_LEN, buf);
    if(buf[0] == 0 && os_memcmp(buf, buf + 1, MAX_BTCV_PASSWORD_LEN - 1) == 0)
        return false;
    return true;
}

unsigned short btchip_apdu_set_btcv_password()
{
    unsigned char passwordBuffer[MAX_BTCV_PASSWORD_LEN];
    unsigned char passwordType = G_io_apdu_buffer[ISO_OFFSET_P1];
    PRINTF("btchip_apdu_set_btcv_password, passwordType: %c\n", passwordType);
    PRINTF("btcvInstantPassword:\n%.*H\n", MAX_BTCV_PASSWORD_LEN, N_btchip.btcvInstantPassword);
    PRINTF("btcvRecoveryPassword:\n%.*H\n", MAX_BTCV_PASSWORD_LEN, N_btchip.btcvRecoveryPassword);
    os_memset(passwordBuffer, 0, MAX_BTCV_PASSWORD_LEN);
    if(!shouldResetPassword())
    {
        if(!isPasswordSet((void *)&N_btchip.btcvRecoveryPassword) && BTCV_PASSWORD_TYPE_INSTANT == passwordType)
            return BTCHIP_SW_INCORRECT_DATA; // request for instant password setup when recovery password not set
        os_memcpy(passwordBuffer, G_io_apdu_buffer + ISO_OFFSET_CDATA, G_io_apdu_buffer[ISO_OFFSET_LC]);
    }
    else if(isPasswordSet((void *)&N_btchip.btcvInstantPassword) && BTCV_PASSWORD_TYPE_RECOVERY == passwordType)
        return BTCHIP_SW_INCORRECT_DATA; // request for recovery password reset while instant password set
    if(BTCV_PASSWORD_TYPE_INSTANT == passwordType)
        nvm_write((void *)&N_btchip.btcvInstantPassword, passwordBuffer, MAX_BTCV_PASSWORD_LEN);
    if(BTCV_PASSWORD_TYPE_RECOVERY == passwordType)
        nvm_write((void *)&N_btchip.btcvRecoveryPassword, passwordBuffer, MAX_BTCV_PASSWORD_LEN);
    PRINTF("btcvInstantPassword:\n%.*H\n", MAX_BTCV_PASSWORD_LEN, N_btchip.btcvInstantPassword);
    PRINTF("btcvRecoveryPassword:\n%.*H\n", MAX_BTCV_PASSWORD_LEN, N_btchip.btcvRecoveryPassword);
    return BTCHIP_SW_OK;
}
