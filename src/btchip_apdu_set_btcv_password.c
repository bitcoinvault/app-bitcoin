#include "btchip_internal.h"
#include "btchip_apdu_constants.h"


bool passwordResetRequested()
{
    return G_io_apdu_buffer[ISO_OFFSET_LC] == 1 && G_io_apdu_buffer[0] == 0x00;
}

bool isPasswordSet(char *buf)
{
    if(buf[0] == 0 && os_memcmp(buf, buf + 1, MAX_BTCV_PASSWORD_LEN - 1) == 0)
        return false;
    return true;
}

void btchip_bagl_btcv_password_confirmation_display(unsigned int confirming)
{
    unsigned short sw = BTCHIP_SW_OK;
    if (!os_global_pin_is_validated())
    {
        sw = BTCHIP_SW_SECURITY_STATUS_NOT_SATISFIED;
        btchip_context_D.outLength = 0;
    }
    // confirm and finish the apdu exchange
    else if (confirming)
    {
        unsigned char passwordBuffer[MAX_BTCV_PASSWORD_LEN];
        unsigned char changedPasswordType = G_io_apdu_buffer[ISO_OFFSET_P1];
        os_memset(passwordBuffer, 0, MAX_BTCV_PASSWORD_LEN);
        os_memcpy(passwordBuffer, G_io_apdu_buffer + ISO_OFFSET_CDATA, G_io_apdu_buffer[ISO_OFFSET_LC]);
 
        btchip_context_D.outLength -= 2; // status was already set by the last call
        if(changedPasswordType == BTCV_PASSWORD_TYPE_INSTANT)
        {
            nvm_write((void *)&N_btchip.btcvInstantPassword, passwordBuffer, MAX_BTCV_PASSWORD_LEN);
        }
        if(changedPasswordType == BTCV_PASSWORD_TYPE_RECOVERY)
        {
            nvm_write((void *)&N_btchip.btcvRecoveryPassword, passwordBuffer, MAX_BTCV_PASSWORD_LEN);
        }
    }
    else
    {
        sw = BTCHIP_SW_CONDITIONS_OF_USE_NOT_SATISFIED;
        btchip_context_D.outLength = 0;
    }
    G_io_apdu_buffer[btchip_context_D.outLength++] = sw >> 8;
    G_io_apdu_buffer[btchip_context_D.outLength++] = sw;

    PRINTF("end btcvInstantPassword:\n%.*H\n", MAX_BTCV_PASSWORD_LEN, N_btchip.btcvInstantPassword);
    PRINTF("end btcvRecoveryPassword:\n%.*H\n", MAX_BTCV_PASSWORD_LEN, N_btchip.btcvRecoveryPassword);
    io_exchange(CHANNEL_APDU | IO_RETURN_AFTER_TX, btchip_context_D.outLength);
}

unsigned short btchip_apdu_set_btcv_password()
{
    unsigned char passwordType = G_io_apdu_buffer[ISO_OFFSET_P1];
    PRINTF("btchip_apdu_set_btcv_password, passwordType: %c\n", passwordType);
    PRINTF("btcvInstantPassword:\n%.*H\n", MAX_BTCV_PASSWORD_LEN, N_btchip.btcvInstantPassword);
    PRINTF("btcvRecoveryPassword:\n%.*H\n", MAX_BTCV_PASSWORD_LEN, N_btchip.btcvRecoveryPassword);
 
    if(!passwordResetRequested())
    {
        if(!isPasswordSet((void *)&N_btchip.btcvRecoveryPassword) && BTCV_PASSWORD_TYPE_INSTANT == passwordType)
            return BTCHIP_SW_INCORRECT_DATA; // request for instant password setup when recovery password not set
    }
    else if(isPasswordSet((void *)&N_btchip.btcvInstantPassword) && BTCV_PASSWORD_TYPE_RECOVERY == passwordType)
        return BTCHIP_SW_INCORRECT_DATA; // request for recovery password reset while instant password set

    if(BTCV_PASSWORD_TYPE_INSTANT == passwordType)
    {
        btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
        btchip_bagl_set_btcv_instant_password_approval();
    }
    if(BTCV_PASSWORD_TYPE_RECOVERY == passwordType)
    {
        btchip_context_D.io_flags |= IO_ASYNCH_REPLY;
        btchip_bagl_set_btcv_recovery_password_approval();
    }
    return BTCHIP_SW_OK;
}
