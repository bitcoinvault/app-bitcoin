import pytest
from dataclasses import dataclass, field
from typing import Optional, List
from helpers.basetest import BaseTestBtc
from helpers.deviceappbtc import DeviceAppBtc, BTC_P1, BTC_P2

@dataclass
class PrevTxData:
    # Tx to compute a TrustedInput from.
    tx: bytes
    # List of lengths of the chunks that will be sent as APDU payloads. Depending on the APDU
    # the APDU, the BTC app accepts payloads (composed from the tx and other data) of specific
    # sizes. See https://blog.ledger.com/btchip-doc/bitcoin-technical-beta.html#_get_trusted_input.
    chunks_len: List[int]
    # List of the outputs values to be tested, as expressed in the raw tx.
    prevout_amount: List[bytes]
    # Optional, index (not offset!) in the tx of the output to compute the TrustedInput from. Ignored
    # if num_outputs is set.
    prevout_idx: Optional[int] = field(default=None)
    # Optional, number of outputs in the tx. If set, all the tx outputs will be used to generate
    # each a corresponding TrustedInput, prevout_idx is ignored and prevout_amount must contain the
    # values of all the outputs of that tx, in order. If not set, then prevout_idx must be set.
    num_outputs: Optional[int] = field(default=None)

# non segwit utxo
prev_tx_data = PrevTxData(
    tx=bytes.fromhex(
        # Version
        "02000000"
        # Input count
        "01"
        # Prevout hash (txid) @offset 7
        "eeeb3a48a5d86876560c088072fc03518cbca1e2c6550a605a7837e1cb7a8778"
        # Prevout index @offset 39
        "00000000"
        # scriptSig @offset 43
        "48"
        "47304402202a67eed3e10f728548125f0622d121a366989c9cba2e9b43631f3e5cdc61f9040220041f2653f09cb49b0793ee426239c104be85621156dcb6f5da6286395fb1976a01"
        # Input sequence @offset 67
        "feffffff"
            # Output count @offset 135
        "02"
            # Amount #1 @offset (8 bytes) 136
        "00ab904100000000"
            # scriptPubkey #1 (24 bytes) @offset 144
        "17"
        "a914f081bdd00bd0a2dd4feb042bd83a4c3afa5ab63e87"

        "641584d103000000"
        "17"
        "a914391c61720f6414e38cce36161f077273c04dccdc87"
            # locktime @offset -4
        "65000000"),
        chunks_len=[(4+4+1), (32+4+1), -1, 1, 9, 32, 27 ],
        # chunks_len=[(4 + 4, 2, 1), 37, 4, 37, 4, 1, 31, 4],
        prevout_idx=0,
        prevout_amount=[bytes.fromhex("01410f0000000000")]
)

#s egwit utxo
prev_tx_data2 = PrevTxData(
    tx=bytes.fromhex(
        # Version no (4 bytes)
        "02000000"
        # Marker + Flag (optional 2 bytes, 0001 indicates the presence of witness data)
        # /!\ Remove flag for `GetTrustedInput`
        "0001"
        # In-counter (varint 1-9 bytes)
        "02"
        # Previous Transaction hash 1 (32 bytes)
        "daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a9"
        # Previous Txout-index 1 (4 bytes)
        "00000000"
        # Txin-script length 1 (varint 1-9 bytes)
        "00"
        # /!\ no Txin-script (a.k.a scriptSig) because P2WPKH
        # sequence_no (4 bytes)
        "fdffffff"
        # Previous Transaction hash 2 (32 bytes)
        "daf4d7b97a62dd9933bd6977b5da9a3edb7c2d853678c9932108f1eb4d27b7a9"
        # Previous Txout-index 2 (4 bytes)
        "01000000"
        # Tx-in script length 2 (varint 1-9 bytes)
        "00"
        # sequence_no (4 bytes)
        "fdffffff"
        # Out-counter (varint 1-9 bytes)
        "01"
        # value in satoshis (8 bytes)
        "01410f0000000000"  # 999681 satoshis = 0,00999681 BTC
        # Txout-script length (varint 1-9 bytes)
        "16"  # 22
        # Txout-script (a.k.a scriptPubKey)
        "0014e4d3a1ec51102902f6bbede1318047880c9c7680"
        # Witnesses (1 for each input if Flag=0001)
        # /!\ remove witnesses for `GetTrustedInput`

        # "0247"
        # "30440220495838c36533616d8cbd6474842459596f4f312dce5483fe650791c8"
        # "2e17221c02200660520a2584144915efa8519a72819091e5ed78c52689b24235"
        # "182f17d96302012102ddf4af49ff0eae1d507cc50c86f903cd6aa0395f323975"
        # "9c440ea67556a3b91b"
        # "0247"
        # "304402200090c2507517abc7a9cb32452aabc8d1c8a0aee75ce63618ccd90154"
        # "2415f2db02205bb1d22cb6e8173e91dc82780481ea55867b8e753c35424da664"
        # "f1d2662ecb1301210254c54648226a45dd2ad79f736ebf7d5f0fc03b6f8f0e6d"
        # "4a61df4e531aaca431"

        # lock_time (4 bytes)
        "a7011900"
    ),
        # First tuple in list below is used to concatenate output_idx||version||input_count while
        # skip the 2-byte segwit-specific flag ("0001") in between.
        # Value 341 = locktime offset in APDU payload (i.e. skip all witness data).
        # Finally, tx contains no scriptSig, so no "-1" trick is necessary.
    # chunks_len= [(4+4, 2, 1), 37, 4, 37, 4, 1, 31, (335+4, 4)],
    chunks_len=[(4 + 4, 2, 1), 37, 4, 37, 4, 1, 31, 4],
    prevout_idx=0,
    prevout_amount=[bytes.fromhex("01410f0000000000")]
)

@pytest.mark.btc
@pytest.mark.manual
class TestBtcvTxSignature(BaseTestBtc):

    # test_data = [ prev_tx ]

    @pytest.mark.parametrize("testdata", [3])
    def test_btcv_signature(self, testdata: int) -> None:
        btc = DeviceAppBtc()

        prevout_idx = [idx for idx in range(prev_tx_data.num_outputs)] \
            if prev_tx_data.num_outputs is not None else [prev_tx_data.prevout_idx]

        # Get TrustedInputs for all requested outputs in the tx
        trusted_input = btc.getTrustedInput(
                data=prevout_idx[0].to_bytes(4, 'big') + prev_tx_data.tx,
                chunks_len=prev_tx_data.chunks_len)

        print("trusted inputs: ", bytearray(trusted_input).hex())
