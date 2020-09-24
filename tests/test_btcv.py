import pytest
from typing import Optional, List
from functools import reduce
from helpers.basetest import BaseTestBtc, BtcPublicKey, TxData
from helpers.deviceappbtc import DeviceAppBtc

@pytest.mark.btc
@pytest.mark.manual
class TestBtcTxSignature(BaseTestBtc):

    @pytest.mark.parametrize("test_data", [3])
    def test_submit_trusted_segwit_input_btc_transaction(self, test_data: int) -> None:
        btc = DeviceAppBtc()
        print("\n--* Test running")

        newInstantPassword = "dupa".encode('utf-8').hex();
        newRecoveryPassword = "123".encode('utf-8').hex();

        btc.setBtcvPassword(p1="00", data=newInstantPassword)
        btc.setBtcvPassword(p1="01", data=newRecoveryPassword)
