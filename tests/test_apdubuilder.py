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

test_ms = TestData(prevout_data = PrevoutData(trusted_input_index="00000000",
                                              version="02000000",
                                              prevtxid="8f8faf768d751a51402aa6fd96f223555b90dd8dc6d9bbf5ad42a6bf5c440449",
                                              prevn="00000000",
                                              scriptsig="473044022046c79c2ded548c46a357dd69965eeebb0217547860a18e2048b197c1fc1a375b02204bb399fc7aec43ecf01d6fd5d6077ab3f9661a90960ff813d6f6c97afd67522c01",
                                              sequence="feffffff",
                                              outputs=["00ab90410000000017a9144d19b4a6e4676043f015221df9d6aa83b703598887", "641584d10300000017a9145566de026561ea9cf58547e934ee1623a00cbc3787"],
                                              locktime="65000000"),
                   tx_to_sign_inputs=TxToSignInputs(version="02000000",
                                                    # trustedinput="3200b85ff607c8b58f2679175d83481324983676d5b06167ee8f88ac36956c4e0040cfc90000000000ab904100000000a85e707195e0ef50",
                                                    trustedinput="",
                                                    redeemscript="514104478ecc8e902485b66c32b4bc500037e76458f86430ab32393d2c8eacf179b14d2dfead5d0858a4a7bce8d828abc9d29353c65e7b583b86154957a696814e84794104408cdf535029651f4167ea7dfa7e88c2255f325f086649b9fa6c6c1691591b22cb4d29919d932e55e1122b19cadde3b34462cc0679a3a59badc6679d8a85620341045939d3dea2a8775e25dab4a4ab0eed4e25e3b2c37c4d0a5985b50fae302220a48c43a47024c8eaee21b0752e77007ba7677a1df1c26266538d976693f5b00b9f53ae",
                                                    sequence="ffffffff",
                                                    use_trusted_input=True),
                   tx_to_sign_outputs=TxToSignOutputs(outputs=["c0a695350000000017a91453cd9595b975a9dd33484753dcd29d5895d013ea87", "c07fdc0b0000000017a9141f70d71e9b8f2711cffa3dca62e95e3199fb9b7087"],
                                                      locktime="65000000",
                                                      signingpath="05""8000002C""800001B8""80000000""00000000""00000000"),
                   expected_result="304402206027fc850cd4b7768d23d019493b0c262004382ff47757e90f5352e170cca7ee02201c0a76ffbfbf9196d12d6ee90c7dad88aa4607804e2305949607fefce75fef1901"
                   )


test_ljs = TestData(prevout_data = PrevoutData(trusted_input_index="00000001",
                                              version="01000000",
                                              prevtxid="4ea60aeac5252c14291d428915bd7ccd1bfc4af009f4d4dc57ae597ed0420b71",
                                              prevn="01000000",
                                              scriptsig="47304402201f36a12c240dbf9e566bc04321050b1984cd6eaf6caee8f02bb0bfec08e3354b022012ee2aeadcbbfd1e92959f57c15c1c6debb757b798451b104665aa3010569b49014104090b15bde569386734abf2a2b99f9ca6a50656627e77de663ca7325702769986cf26cc9dd7fdea0af432c8e2becc867c932e1b9dd742f2a108997c2252e2bdeb",
                                              sequence="ffffffff",
                                              outputs=["81b72e00000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac", "a0860100000000001976a9144533f5fb9b4817f713c48f0bfe96b9f50c476c9b88ac"],
                                              locktime="00000000"),
                    tx_to_sign_inputs=TxToSignInputs(version="01000000",
                                                     trustedinput="",
                                                     redeemscript="52210289b4a3ad52a919abd2bdd6920d8a6879b1e788c38aa76f0440a6f32a9f1996d02103a3393b1439d1693b063482c04bd40142db97bdf139eedd1b51ffb7070a37eac321030b9a409a1e476b0d5d17b804fcdb81cf30f9b99c6f3ae1178206e08bc500639853ae",
                                                     sequence="ffffffff",
                                                     use_trusted_input=False),
                    tx_to_sign_outputs=TxToSignOutputs(outputs=["905f0100000000001976a91472a5d75c8d2d0565b656a5232703b167d50d5a2b88ac"],
                                                       locktime="00000000",
                                                       signingpath="03""80000000""00000000""00000000"),
                    expected_result="3045022100a753fcc4c3befd6208b2f8ffd5cc2a8de276d4c3ce9b1d5546b04ccb74dafa6802203b6e429f9e5c710f70b263873ebc3c745dc17daa64a2ef386742b9a4cc4efd7501"
                    )


@pytest.mark.manual
@pytest.mark.btc
class TestApduBuilder(BaseTestBtc):

    apdu_test_data = [test_ljs, test_ms]

    @pytest.mark.parametrize('test_data', apdu_test_data)
    def test_replay_ledgerjs_tests(self, test_data: TestData) -> None:

        btc = DeviceAppBtc()

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

        assert(response.hex() == test_data.expected_result)
