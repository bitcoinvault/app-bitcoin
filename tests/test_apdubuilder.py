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
class TxToSignInput:
    version: str
    trustedinput: str
    redeemscript: str
    sequence: str
    use_trusted_input: bool

@dataclass
class TxToSignOutputs:
    outputs: List[str]
    locktime: str
    signingpaths: List[str]

@dataclass
class TestData:
    prevouts_data: List[PrevoutData]
    tx_to_sign_inputs: List[TxToSignInput]
    tx_to_sign_outputs: TxToSignOutputs
    expected_alert_results: List[str]
    expected_instant_results: List[str]
    expected_recovery_results: List[str]

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

def prepare_untrusted_hash_tx_input_apdu(inputs, index_to_sign):
    untrustedHashTxInputStart = LedgerjsApdu(commands=[])
    untrustedHashTxInputStart.commands.append("e044000005" + inputs[0].version + "0" + hex(len(inputs))[2:])
    input_index = 0
    for input in inputs:
        if(input_index == index_to_sign):
            redeemscript = input.redeemscript
        else:
            redeemscript = ""
        print("sending input ", input_index, ", redeemscript: ", redeemscript)
        if(input.use_trusted_input == True):
            apdu_payload = "01" + item_bytes_len(input.trustedinput) + input.trustedinput + item_bytes_len(redeemscript)
        else:
            apdu_payload = "00" + input.trustedinput[8:-32] + item_bytes_len(redeemscript)
        untrustedHashTxInputStart.commands.append(apdu_from_payload(apdu_payload, "44"))
        redeemscript_left = redeemscript
        while (len(redeemscript_left) >= 100):
            untrustedHashTxInputStart.commands.append(apdu_from_payload(redeemscript_left[:100], "44"))
            redeemscript_left = redeemscript_left[100:]
            print("redeemscript_left: ", redeemscript_left)
        untrustedHashTxInputStart.commands.append(apdu_from_payload(redeemscript_left + input.sequence, "44"))
        input_index = input_index + 1
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

def prepare_untrusted_hash_sign(tx_to_sign_outputs, index_to_sign):
    untrustedHashSign = LedgerjsApdu(commands=[])  # UNTRUSTED HASH SIGN
    payload = tx_to_sign_outputs.signingpaths[index_to_sign] + "00" + tx_to_sign_outputs.locktime + "01"
    untrustedHashSign.commands.append("e0480000" + item_bytes_len(payload) + payload)
    return untrustedHashSign

test_alert_single_input = TestData(prevouts_data = [PrevoutData(trusted_input_index="00000000",
                                                                version="02000000",
                                                                prevtxid="0404bbabf58a527299178e4f5ba6f5bdff2c5fd85ac1f412cb75aaff5353ad83",
                                                                prevn="00000000",
                                                                scriptsig="473044022038479cf30be734181af03fbb6b3b7059d8e17dbb370924a2e98cf59dc5280ee502203af3414c6d944a79c0e409423490bb23b3c6865a02cd04827422513a76e0050801",
                                                                sequence="feffffff",
                                                                outputs=["00ab90410000000017a91447d8c9cd8f60b13c7cf2397eb7c121cbf7d9cff587", "641584d10300000017a914a286dde661c73740f69afdd16422032d7a1b8dd687"],
                                                                locktime="65000000")],
                                    tx_to_sign_inputs = [TxToSignInput( version="02000000",
                                                                        trustedinput="",
                                                                        redeemscript="635167635267536868410450831f9831a46e3b264034ae2d8ef24555a2aa9e66579eab91e4a7c7794e01c7f4c88aff1f69c6acfd2f857f33dbf102a9b79429828110447d0743f705e6bcd041048f54726f142383fe06f7385d6445b44d6f0a0dac7bdd7a6ea7dec21cdd7115777d4305aabd65b8566055cddd0135efb617718c0fc92d174d89452bb43b78061a4104d96eb418af0c6659526f236452d96b5f5c0bf0469ba824868e58ba25c66eba9cf63a0d84eac158aa976c17328ac1ae75c7c9949f8c57571e046c8e8642fdf44053ae",
                                                                        sequence="ffffffff",
                                                                        use_trusted_input=True)],
                                    tx_to_sign_outputs=TxToSignOutputs(outputs=["c0a695350000000017a9140f4de5d62f29e58670012fc4588cbfff7f3ef0f787", "c07fdc0b0000000017a914963c74d26ec7787f4f17c6d8d7f6c756da41e9a387"],
                                                                       locktime="00000000",
                                                                       signingpaths=["04""8000002D""00000001""00000001""00000000"]),
                                    expected_alert_results=["314402207034c4bbe48afb53f39b0ef34587ca33ec37e1e412ab75832b23d30bf9880cbf02205878b75e7b0da6a6ff79d268b2de5fa6653f994f6c730c0c773fe2ab5ad0d19c01"],
                                   expected_instant_results=["314402202f9fa47113ac588b429ba7eb2283a05701674946036cad5ca367888b3d840c31022054ed701a27dceac367735d8ca8029dba3aa6055162fbe5239d218397a933ea1601"],
                                   expected_recovery_results=["3045022100b79a6f829e803c149fbe3f6612cfe8f765cf0942c635f936ffd20c47533e71ea0220172e6b37b7a2f644d49f01ba4a28670277ec54428251ffef9e0dd1290fbd60db01"]
                                    )

test_alert_two_inputs = TestData(prevouts_data = [PrevoutData(trusted_input_index="00000000",
                                                                version="02000000",
                                                                prevtxid="4b89844a7cb28e26019fe614ad0341bae8edbd2bdfd238a3ee732be22c820f8f",
                                                                prevn="01000000",
                                                                scriptsig="160014c3cecd8a9609241b26bb9740c722a811c348bef5",
                                                                sequence="feffffff",
                                                                outputs=["00c2eb0b0000000017a914d77d59e74b5893e23bd8d4cfc167dc459312546b87",
                                                                         "6c2f3dfb0300000017a91468ec44f6761d3e6d8e8c49fb3ec58b0ff767314787"],
                                                                locktime="4d000000"),
                                                  PrevoutData(trusted_input_index="00000000",
                                                              version="02000000",
                                                              prevtxid="3964972289e2d6fe7d22e654f5376cac4711df04d8678ac752f8e02a3bb26166",
                                                              prevn="00000000",
                                                              scriptsig="473044022000de3af92753a6239214f1ea1b0f723ccebe33910f0ce7fec69954b90d31188302200f409213936dc88cdd9dc2b2eba81fd7fc7305af74ea80034752c16b9ca95dbb01",
                                                              sequence="feffffff",
                                                              outputs=[
                                                                  "00c2eb0b0000000017a914cc441973740a8b42d2227cd36dd663c085ad784987",
                                                                  "64fe28070400000017a9148434e0f6b5fd6075df278b1eb0c3e2fe9a71ccd187"],
                                                              locktime="65000000")],
                                    tx_to_sign_inputs = [TxToSignInput( version="02000000",
                                                                        trustedinput="",
                                                                        redeemscript="63516763526753686821022DDCBB051A5DB0733FA40FD2DCA84014882380AC8A3AA78BEC6619713B64AE7E21028F54726F142383FE06F7385D6445B44D6F0A0DAC7BDD7A6EA7DEC21CDD7115772102D96EB418AF0C6659526F236452D96B5F5C0BF0469BA824868E58BA25C66EBA9C53AE",
                                                                        sequence="fdffffff",
                                                                        use_trusted_input=False),
                                                         TxToSignInput(version="02000000",
                                                                       trustedinput="",
                                                                       redeemscript="63516763526753686821020F355163909754B4E627D1240A3A942426B5239C38B68F04CCFABA2F9BE6DBD621028F54726F142383FE06F7385D6445B44D6F0A0DAC7BDD7A6EA7DEC21CDD7115772102D96EB418AF0C6659526F236452D96B5F5C0BF0469BA824868E58BA25C66EBA9C53AE",
                                                                       sequence="fdffffff",
                                                                       use_trusted_input=False)],
                                    tx_to_sign_outputs=TxToSignOutputs(outputs=["0882d7170000000017a91430d5b88a641c64cabbfd8b7879c42f7b9cc394c887"],
                                                                       locktime="00000065",
                                                                       signingpaths=["05""8000002D""00000001""00000001""00000000""00000001", "05""8000002D""00000001""00000001""00000000""00000000"]),
                                    expected_alert_results=["31440220764f1148502866ce3d36193d64b852f958487ba1f14dbe54aca7ba5d5c77e06c02205327923346e8bffcf03ae1f78fa0d40e95e6109a4ca4f55b4f0bc25a7746601501",
                                                            "304402202da7d2024cc0c915692af8aa25144a3c2dcbcc47440de9b757ec476ba4d5118a02206e536dc20e4ef3c3da5da45cf92ecf94ebd15d8c04d281d14a8cbc6e29b3ee6501"],
                                    expected_instant_results=["3045022100e1dc0d9a41bb03827cad6f02c6385c5cabf01bc64204aacea2f2e85a0e7829360220587636398ce3d93cfc80684f28174a1789961686c0f78efef636a33b09fab5ee01",
                                                              "3045022100ca45bad3e98c3b21df1825c38b0f306a5a165c8e3ce4338700306e1d2874e55e022035970dab315022145e0d695c849234255d767a6aaa3e4f0ef9dbf15808644a7001"],
                                    expected_recovery_results=["3045022100bc8f936fd644a3b0c5e46eb033e7ae3ad897e3403bb4f2f90f1af5ee021f794d02201d9a2463ab69f1b0d30f7b311e40c2b01c2d734193dce32b2ea4b1d197920ba201",
                                                               "3045022100ad6ba8be605a18534eed04dc71bf9b1a528916b2c457092ecaf8e0f1e87c0b8c02202005bbdf376dd140774d72086cd24d351dade5b23a2a4913facc96b51eaba33601"]
                                    )

@pytest.mark.manual
@pytest.mark.btc
class TestApduBuilder(BaseTestBtc):

    apdu_test_data = [test_alert_single_input, test_alert_two_inputs]

    @pytest.mark.parametrize('test_data', apdu_test_data)
    def test_btcv_3keys_signature(self, test_data: TestData) -> None:

        btc = DeviceAppBtc()

        newInstantPassword = "0123"
        newRecoveryPassword = "abcd"
        btc.setBtcvPassword(p1="01", data=newRecoveryPassword)
        btc.setBtcvPassword(p1="00", data=newInstantPassword)

        trustedInputsApdu = [prepare_trusted_input_apdu(prevout_data) for prevout_data in (test_data.prevouts_data)]

        inputIndex=0
        for trustedInputApdu in trustedInputsApdu:
            for command in trustedInputApdu.commands:
                response = btc.sendRawApdu(bytes.fromhex(command))
            test_data.tx_to_sign_inputs[inputIndex].trustedinput = response.hex()
            inputIndex=inputIndex+1

        for i in range(inputIndex):
            untrustedHashTxInputStart = prepare_untrusted_hash_tx_input_apdu(test_data.tx_to_sign_inputs, i)
            for command in untrustedHashTxInputStart.commands:
                response = btc.sendRawApdu(bytes.fromhex(command))

            untrustedHashTxInputFinalize = prepare_untrusted_hash_tx_finalize_apdu(test_data.tx_to_sign_outputs)
            for command in untrustedHashTxInputFinalize.commands:
                response = btc.sendRawApdu(bytes.fromhex(command))

            untrustedHashSign = prepare_untrusted_hash_sign(test_data.tx_to_sign_outputs, i)
            for command in untrustedHashSign.commands:
                response = btc.sendRawApdu(bytes.fromhex(command))

            print("Signature: ", response.hex())

            assert (response.hex() == test_data.expected_alert_results[i])

        for i in range(inputIndex):
            untrustedHashTxInputStart = prepare_untrusted_hash_tx_input_apdu(test_data.tx_to_sign_inputs, i)
            for command in untrustedHashTxInputStart.commands:
                response = btc.sendRawApdu(bytes.fromhex(command))

            untrustedHashTxInputFinalize = prepare_untrusted_hash_tx_finalize_apdu(test_data.tx_to_sign_outputs)
            for command in untrustedHashTxInputFinalize.commands:
                response = btc.sendRawApdu(bytes.fromhex(command))

            passwordHash = "49EB9DA9B0BF0F36DC17FEF23F7002A7FD502E0F4F8475F76F0F07BEA229E324"
            response = btc.useBtcvSignaturePassword(p1="01", data=passwordHash)

            untrustedHashSign = prepare_untrusted_hash_sign(test_data.tx_to_sign_outputs, i)
            for command in untrustedHashSign.commands:
                response = btc.sendRawApdu(bytes.fromhex(command))

            print("Signature 2: ", response.hex())

            assert (response.hex() == test_data.expected_instant_results[i])

        for i in range(inputIndex):
            untrustedHashTxInputStart = prepare_untrusted_hash_tx_input_apdu(test_data.tx_to_sign_inputs, i)
            for command in untrustedHashTxInputStart.commands:
                response = btc.sendRawApdu(bytes.fromhex(command))

            untrustedHashTxInputFinalize = prepare_untrusted_hash_tx_finalize_apdu(test_data.tx_to_sign_outputs)
            for command in untrustedHashTxInputFinalize.commands:
                response = btc.sendRawApdu(bytes.fromhex(command))

            passwordHash = "969EB1C17FA7B6F45D3773FC8B7534324C828779173E7AA1FE9FDFDD333BED8D"
            response = btc.useBtcvSignaturePassword(p1="02", data=passwordHash)

            untrustedHashSign = prepare_untrusted_hash_sign(test_data.tx_to_sign_outputs, i)
            for command in untrustedHashSign.commands:
                response = btc.sendRawApdu(bytes.fromhex(command))

            print("Signature 3: ", response.hex())

            assert (response.hex() == test_data.expected_recovery_results[i])
