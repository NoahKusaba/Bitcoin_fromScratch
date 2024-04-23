from dataclasses import dataclass
from typing import List, Union
from hashlib import sha256
from transaction.digital_signiture import  sign
"""
- Transactions on Bitcoin:
    - One source wallet:
        - Two Destination wallets
        - All money from source wallet must be spent in transaction, so remainder must output back to source.
    - Sum of money leaving source, must be less than delivered (gas fees & prevent printing money)
    - Sourced from Andrej Karpathy Bitcoin Blog

"""

def encode_int(i, nbytes, encoding='little'):
    """ encode integer i into nbytes bytes using a given byte ordering """
    return i.to_bytes(nbytes, encoding)

def encode_varint(i):
    """ encode a (possibly but rarely large) integer into bytes with a super simple compression scheme """
    if i < 0xfd:
        return bytes([i])
    elif i < 0x10000:
        return b'\xfd' + encode_int(i, 2)
    elif i < 0x100000000:
        return b'\xfe' + encode_int(i, 4)
    elif i < 0x10000000000000000:
        return b'\xff' + encode_int(i, 8)
    else:
        raise ValueError("integer too large: %d" % (i, ))

# Creating serialized instruction set to transact bitcoin between wallets
@dataclass
class Script:
    # Converts Op Codes and passed Public Keys to resultant script for transaction 
    cmds: List[Union[int, bytes]]

    def encode(self):
        out = []
        for cmd in self.cmds:
            if isinstance(cmd, int):
                # an int is just an opcode, encode as a single byte
                out += [encode_int(cmd, 1)]
            elif isinstance(cmd, bytes):
                # bytes represent an element, encode its length and then content
                length = len(cmd)
                assert length < 75 # any longer than this requires a bit of tedious handling that we'll skip here
                out += [encode_int(length, 1), cmd]

        ret = b''.join(out)
        return encode_varint(len(ret)) + ret

@dataclass
class TxIn: 
    prev_tx: bytes # previous trx id, hash 256 of trx contents
    prev_index: int # UTXO output index in the transaction
    secret_key: int # secret key of soure wallet
    public_key_hash : str
    public_key_bytes : bytes
    prev_tx_script_pubkey: Script
    script_sig: Script = None # unlocking script, Script class coming a bit later below
    sequence: int = 0xffffffff # originally intended for "high frequency trades", with locktime

    def encode(self, script_override=None):
        out = []
        out += [self.prev_tx[::-1]] # little endian vs big endian encodings... sigh
        out += [encode_int(self.prev_index, 4)]

        if script_override is None:
            # None = just use the actual script
            out += [self.script_sig.encode()]
        elif script_override is True:
            # True = override the script with the script_pubkey of the associated input
            out += [self.prev_tx_script_pubkey.encode()]
        elif script_override is False:
            # False = override with an empty script
            out += [Script([]).encode()]
        else:
            raise ValueError("script_override must be one of None|True|False")

        out += [encode_int(self.sequence, 4)]
        return b''.join(out)
    
@dataclass
class TxOut:
    amount:int
    public_key_hash : str
    script_pubkey: Script = None
    def encode(self):
        out = []
        out += [encode_int(self.amount, 8)]
        out += [self.script_pubkey.encode()]
        return b''.join(out)

@dataclass
class Tx:
    version: int
    tx_ins: List[TxIn]
    tx_outs: List[TxOut]
    locktime: int = 0

    def encode(self, sig_index=-1) -> bytes:
        """
        Encode this transaction as bytes.
        If sig_index is given then return the modified transaction
        encoding of this tx with respect to the single input index.
        This result then constitutes the "message" that gets signed
        by the aspiring transactor of this input.
        """
        out = []
        # encode metadata
        out += [encode_int(self.version, 4)]
        # encode inputs
        out += [encode_varint(len(self.tx_ins))]
        if sig_index == -1:
            # we are just serializing a fully formed transaction
            out += [tx_in.encode() for tx_in in self.tx_ins]
        else:
            # used when crafting digital signature for a specific input index
            out += [tx_in.encode(script_override=(sig_index == i))
                    for i, tx_in in enumerate(self.tx_ins)]
        # encode outputs
        out += [encode_varint(len(self.tx_outs))]
        out += [tx_out.encode() for tx_out in self.tx_outs]
        # encode... other metadata
        out += [encode_int(self.locktime, 4)]
        out += [encode_int(1, 4) if sig_index != -1 else b''] # 1 = SIGHASH_ALL
        return b''.join(out)
    
    def id(self): return sha256(sha256(self.encode()).digest()).digest()[::-1].hex()


    def generate_encoding(self) :
        # See https://en.bitcoin.it/wiki/Transaction for encoding rules. 
        
        for tx_in in self.tx_ins:
            tx_in.script_pubkey = Script([118, 169, tx_in.public_key_hash, 136, 172 ])

        for tx_out in self.tx_outs:
            tx_out.script_pubkey = Script([118, 169, tx_out.public_key_hash, 136, 172 ])
        
        message= self.encode(sig_index = 0 )

        for tx_in in self.tx_ins:

            sig = sign(tx_in.secret_key, message)
            sig_bytes_and_type = sig.encode() + b'\x01'
            tx_in.script_sig = Script([sig_bytes_and_type, tx_in.public_key_bytes])

        return self.encode().hex()