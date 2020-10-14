import pytest
from typing import Optional, List
from functools import reduce
from helpers.basetest import BaseTestBtc, BtcPublicKey, TxData
from helpers.deviceappbtc import DeviceAppBtc

## key generation is dependant on device seed
## seed used for testing purposes:
## unique inmate age fade dizzy cigar glad theme grief this cargo clerk

newInstantPassword = "abcd".encode('utf-8').hex();
newRecoveryPassword = "123".encode('utf-8').hex();

output_paths = [
    bytes.fromhex("05""8000002C""800001B8""80000000""00000000""00000001"),  # 44'/440'/0'/0/1
    bytes.fromhex("04""8000002C""800001B8""80000000""00000000"),   # 44'/440'/0'/0/
]

expected_pubkeys = [
    "5e08ea62a60f5a185c549062ef1b22eb9a304484614a2f791c74f66c95d929",
    "8a101dc28499283c26e7f977e8172b704f5314593b9a4b75a30dbcc3a7993a",
]

expected_pubkeys_instant = [
    "9d9170be6e1e70590fd304cb1e4edaaee8fd4809828a5eb38c51fd3a6249b6",
    "8cd20cf4503d2d5a12243bbe0ebb92cf1a8a4b616d6549b4799643e6a7c179",
]

expected_pubkeys_recovery = [
    "dff50bd1b6982c7eea2ddff26107b38359b451dbbffe244df947a31a5f3843",
    "b913ba3fbcde19d00d96ec046af9ecf171c7d8b6eb493db4efc7fcb513ccfd",
]
# bytes.fromhex("05""8000002C""800001B8""80000000""00000000")  # 44'/440'/0'/0/


@pytest.mark.btc
@pytest.mark.manual
class TestBtcTxSignature(BaseTestBtc):

    @pytest.mark.parametrize("test_data", [3])
    def test_get_btcv_three_public_keys(self, test_data: int) -> None:
        btc = DeviceAppBtc()
        print("\n--* Test running")

        btc.setBtcvPassword(p1="00", data=newInstantPassword)
        btc.setBtcvPassword(p1="01", data=newRecoveryPassword)
        #
        btc.getWallet3KeysAddress(output_paths[0])
        btc.getWallet3KeysAddress(output_paths[1])

        print("\n--* Get Wallet Public Key - for each tx output path")
        wpk_responses = [btc.getWalletPublicKey(output_path) for output_path in output_paths]
        print("    OK")
        pubkeys_data = [self.split_pubkey_data(data) for data in wpk_responses]
        for pubkey in pubkeys_data:
            print(pubkey)
            assert  pubkey.pubkey_comp[1:].hex() in expected_pubkeys