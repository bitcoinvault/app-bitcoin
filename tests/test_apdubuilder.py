import pytest
from dataclasses import dataclass, field
from typing import List, Optional
from helpers.basetest import BaseTestBtc, LedgerjsApdu
from helpers.deviceappbtc import DeviceAppBtc

## seed used for testing purposes:
## unique inmate age fade dizzy cigar glad theme grief this cargo clerk

@dataclass
class LedgerjsApdu:
    commands: List[str]
    expected_resp: Optional[str] = field(default=None)
    expected_sw: Optional[str] = field(default=None)
    check_sig_format: Optional[bool] = field(default=None)

@dataclass
class PrevoutData:
    trusted_input_index: str
    version: str
    prevtxid: str
    prevn: str
    scriptsig: str
    sequence: str
    outputs: List[str]
    locktime: str

@dataclass
class TxToSignInputs:
    version: str
    trustedinput: str
    redeemscript: str
    sequence: str
    use_trusted_input: bool

@dataclass
class TxToSignOutputs:
    outputs: List[str]
    locktime: str
    signingpath: str

@dataclass
class TestData:
    prevout_data: PrevoutData
    tx_to_sign_inputs: TxToSignInputs
    tx_to_sign_outputs: TxToSignOutputs
    expected_result: str

def item_bytes_len(item):
    apdu_len = int(len(item) / 2)
    apdu_len = hex(apdu_len)[2:]
    if(len(apdu_len) % 2 == 1):
        apdu_len = "0" + apdu_len
    return apdu_len

def apdu_from_payload(payload, ins):
    return "e0" + ins +"8000" + item_bytes_len(payload) + payload

def prepare_trusted_input_apdu(prevout_data):
    trustedInputApdu = LedgerjsApdu(commands=[])  # GET TRUSTED INPUT
    trustedInputApdu.commands.append("e042000009" + prevout_data.trusted_input_index + prevout_data.version + "01")
    apdu_payload = prevout_data.prevtxid + prevout_data.prevn + item_bytes_len(prevout_data.scriptsig)
    trustedInputApdu.commands.append(apdu_from_payload(apdu_payload, "42"))
    scriptsig_left = prevout_data.scriptsig
    while (len(scriptsig_left) >= 100):
        trustedInputApdu.commands.append(apdu_from_payload(scriptsig_left[:100], "42"))
        scriptsig_left = scriptsig_left[100:]
    trustedInputApdu.commands.append(apdu_from_payload(scriptsig_left + prevout_data.sequence, "42"))
    trustedInputApdu.commands.append("e0428000" + "01" + "0" + hex(len(prevout_data.outputs))[2:])
    for output in prevout_data.outputs:
        trustedInputApdu.commands.append(apdu_from_payload(output, "42"))
    trustedInputApdu.commands.append(apdu_from_payload(prevout_data.locktime, "42"))
    return trustedInputApdu

def prepare_untrusted_hash_tx_input_apdu(tx_to_sign_inputs):
    untrustedHashTxInputStart = LedgerjsApdu(commands=[])
    untrustedHashTxInputStart.commands.append("e044000005" + tx_to_sign_inputs.version + "01")
    if(tx_to_sign_inputs.use_trusted_input == True):
        apdu_payload = "01" + item_bytes_len(tx_to_sign_inputs.trustedinput) + tx_to_sign_inputs.trustedinput + item_bytes_len(tx_to_sign_inputs.redeemscript)
    else:
        apdu_payload = "00" + tx_to_sign_inputs.trustedinput[8:-32] + item_bytes_len(tx_to_sign_inputs.redeemscript)
    untrustedHashTxInputStart.commands.append(apdu_from_payload(apdu_payload, "44"))
    redeemscript_left = tx_to_sign_inputs.redeemscript
    while (len(redeemscript_left) >= 100):
        untrustedHashTxInputStart.commands.append(apdu_from_payload(redeemscript_left[:100], "44"))
        redeemscript_left = redeemscript_left[100:]
    untrustedHashTxInputStart.commands.append(apdu_from_payload(redeemscript_left + tx_to_sign_inputs.sequence, "44"))
    return untrustedHashTxInputStart

def prepare_untrusted_hash_tx_finalize_apdu(tx_to_sign_outputs):
    untrustedHashTxInputFinalize = LedgerjsApdu(commands=[])  # UNTRUSTED HASH TRANSACTION INPUT FINALIZE FULL
    outputs_left = "0" + hex(len(tx_to_sign_outputs.outputs))[2:]
    for output in tx_to_sign_outputs.outputs:
        outputs_left = outputs_left + output
    while (len(outputs_left) >= 100):
        untrustedHashTxInputFinalize.commands.append(apdu_from_payload(outputs_left[:100], "4a"))
        outputs_left = outputs_left[100:]
    untrustedHashTxInputFinalize.commands.append(apdu_from_payload(outputs_left, "4a"))
    return untrustedHashTxInputFinalize

def prepare_untrusted_hash_sign(tx_to_sign_outputs):
    untrustedHashSign = LedgerjsApdu(commands=[])  # UNTRUSTED HASH SIGN
    payload = tx_to_sign_outputs.signingpath + "00" + tx_to_sign_outputs.locktime + "01"
    untrustedHashSign.commands.append("e0480000" + item_bytes_len(payload) + payload)
    return untrustedHashSign

test_alert_single_input = TestData(prevout_data = PrevoutData(trusted_input_index="00000000",
                                                              version="02000000",
                                                              prevtxid="0404bbabf58a527299178e4f5ba6f5bdff2c5fd85ac1f412cb75aaff5353ad83",
                                                              prevn="00000000",
                                                              scriptsig="473044022038479cf30be734181af03fbb6b3b7059d8e17dbb370924a2e98cf59dc5280ee502203af3414c6d944a79c0e409423490bb23b3c6865a02cd04827422513a76e0050801",
                                                              sequence="feffffff",
                                                              outputs=["00ab90410000000017a91447d8c9cd8f60b13c7cf2397eb7c121cbf7d9cff587", "641584d10300000017a914a286dde661c73740f69afdd16422032d7a1b8dd687"],
                                                              locktime="65000000"),
                                    tx_to_sign_inputs=TxToSignInputs(version="02000000",
                                                                     trustedinput="",
                                                                     redeemscript="635167635267536868410450831f9831a46e3b264034ae2d8ef24555a2aa9e66579eab91e4a7c7794e01c7f4c88aff1f69c6acfd2f857f33dbf102a9b79429828110447d0743f705e6bcd041048f54726f142383fe06f7385d6445b44d6f0a0dac7bdd7a6ea7dec21cdd7115777d4305aabd65b8566055cddd0135efb617718c0fc92d174d89452bb43b78061a4104d96eb418af0c6659526f236452d96b5f5c0bf0469ba824868e58ba25c66eba9cf63a0d84eac158aa976c17328ac1ae75c7c9949f8c57571e046c8e8642fdf44053ae",
                                                                     sequence="ffffffff",
                                                                     use_trusted_input=True),
                                    tx_to_sign_outputs=TxToSignOutputs(outputs=["c0a695350000000017a9140f4de5d62f29e58670012fc4588cbfff7f3ef0f787", "c07fdc0b0000000017a914963c74d26ec7787f4f17c6d8d7f6c756da41e9a387"],
                                                                       locktime="00000000",
                                                                       signingpath="04""8000002D""00000001""00000001""00000000"),
                                    expected_result="314402207034c4bbe48afb53f39b0ef34587ca33ec37e1e412ab75832b23d30bf9880cbf02205878b75e7b0da6a6ff79d268b2de5fa6653f994f6c730c0c773fe2ab5ad0d19c01"
                                    )

@pytest.mark.manual
@pytest.mark.btc
class TestApduBuilder(BaseTestBtc):

    apdu_test_data = [test_alert_single_input]

    @pytest.mark.parametrize('test_data', apdu_test_data)
    def test_replay_ledgerjs_tests(self, test_data: TestData) -> None:

        btc = DeviceAppBtc()

        sign_path = "04""8000002D""00000001""00000001""00000000"

        newInstantPassword = "0123"
        newRecoveryPassword = "abcd"
        btc.setBtcvPassword(p1="00", data=newInstantPassword)
        btc.setBtcvPassword(p1="01", data=newRecoveryPassword)

        resp1 = btc.getWallet3KeysAddress(sign_path)
        # address: 2Myo7fcq7N8xMg66ZmxEKakttxyepVqVTba
        # redeemScript: 635167635267536868410450831f9831a46e3b264034ae2d8ef24555a2aa9e66579eab91e4a7c7794e01c7f4c88aff1f69c6acfd2f857f33dbf102a9b79429828110447d0743f705e6bcd041048f54726f142383fe06f7385d6445b44d6f0a0dac7bdd7a6ea7dec21cdd7115777d4305aabd65b8566055cddd0135efb617718c0fc92d174d89452bb43b78061a4104d96eb418af0c6659526f236452d96b5f5c0bf0469ba824868e58ba25c66eba9cf63a0d84eac158aa976c17328ac1ae75c7c9949f8c57571e046c8e8642fdf44053ae

        print(self.split_pubkey_data(resp1))


        trustedInputApdu = prepare_trusted_input_apdu(test_data.prevout_data)
        for command in trustedInputApdu.commands:
            response = btc.sendRawApdu(bytes.fromhex(command))

        test_data.tx_to_sign_inputs.trustedinput = response.hex()

        untrustedHashTxInputStart = prepare_untrusted_hash_tx_input_apdu(test_data.tx_to_sign_inputs)
        for command in untrustedHashTxInputStart.commands:
            response = btc.sendRawApdu(bytes.fromhex(command))

        untrustedHashTxInputFinalize = prepare_untrusted_hash_tx_finalize_apdu(test_data.tx_to_sign_outputs)
        for command in untrustedHashTxInputFinalize.commands:
            response = btc.sendRawApdu(bytes.fromhex(command))

        untrustedHashSign = prepare_untrusted_hash_sign(test_data.tx_to_sign_outputs)
        for command in untrustedHashSign.commands:
            response = btc.sendRawApdu(bytes.fromhex(command))

        print("Signature 1: ", response.hex())

        assert (response.hex() == test_data.expected_result)

        #
        # trustedInputApdu = prepare_trusted_input_apdu(test_data.prevout_data)
        # for command in trustedInputApdu.commands:
        #     response = btc.sendRawApdu(bytes.fromhex(command))
        #
        # test_data.tx_to_sign_inputs.trustedinput = response.hex()
        #
        # untrustedHashTxInputStart = prepare_untrusted_hash_tx_input_apdu(test_data.tx_to_sign_inputs)
        # for command in untrustedHashTxInputStart.commands:
        #     response = btc.sendRawApdu(bytes.fromhex(command))
        #
        # untrustedHashTxInputFinalize = prepare_untrusted_hash_tx_finalize_apdu(test_data.tx_to_sign_outputs)
        # for command in untrustedHashTxInputFinalize.commands:
        #     response = btc.sendRawApdu(bytes.fromhex(command))
        #
        # passwordHash = "49EB9DA9B0BF0F36DC17FEF23F7002A7FD502E0F4F8475F76F0F07BEA229E324"
        # response = btc.useBtcvSignaturePassword(p1="01", data=passwordHash)
        #
        # untrustedHashSign = prepare_untrusted_hash_sign(test_data.tx_to_sign_outputs)
        # for command in untrustedHashSign.commands:
        #     response = btc.sendRawApdu(bytes.fromhex(command))
        #
        # print("Signature 2: ", response.hex())
        #
        #
        # trustedInputApdu = prepare_trusted_input_apdu(test_data.prevout_data)
        # for command in trustedInputApdu.commands:
        #     response = btc.sendRawApdu(bytes.fromhex(command))
        #
        # test_data.tx_to_sign_inputs.trustedinput = response.hex()
        #
        # untrustedHashTxInputStart = prepare_untrusted_hash_tx_input_apdu(test_data.tx_to_sign_inputs)
        # for command in untrustedHashTxInputStart.commands:
        #     response = btc.sendRawApdu(bytes.fromhex(command))
        #
        # untrustedHashTxInputFinalize = prepare_untrusted_hash_tx_finalize_apdu(test_data.tx_to_sign_outputs)
        # for command in untrustedHashTxInputFinalize.commands:
        #     response = btc.sendRawApdu(bytes.fromhex(command))
        #
        # passwordHash = "969EB1C17FA7B6F45D3773FC8B7534324C828779173E7AA1FE9FDFDD333BED8D"
        # response = btc.useBtcvSignaturePassword(p1="02", data=passwordHash)
        #
        # untrustedHashSign = prepare_untrusted_hash_sign(test_data.tx_to_sign_outputs)
        # for command in untrustedHashSign.commands:
        #     response = btc.sendRawApdu(bytes.fromhex(command))
        #
        # print("Signature 3: ", response.hex())
        #
        # assert(False)
