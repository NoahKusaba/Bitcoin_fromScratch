
from public_key.ecc import Point
from public_key.bitcoin_address import PublicKey
from public_key.ecc import Point
from transaction.transaction import TxIn, TxOut, Script, Tx
from transaction.digital_signiture import sign

if __name__ == '__main__': 

# Generating Identity 1

    # Generate 256 bit Secret key from some byte string 
    secret_key = int.from_bytes(b'asdfa Noah number 2')

    # EDSA Signiture of secret key to produce public_key
    public_key1_point = Point.generate_publicKey(secret_key)

    # Convert Public Key point on Elliptical curve to a bitcoin address (Public Identifier) using the SHA256 Encryption and RIPEMD-160 Encryption 
    bitcoin_address = PublicKey(public_key1_point).get_address(compressed= True)

    print(f"FIRST secret key {secret_key}, \n FIRST public key {public_key1_point}, \n FIRST bitcoin address {bitcoin_address}")

# Generating Identity 2

    # Generate 256 bit Secret key from some byte string 
    secret_key2 = int.from_bytes(b'Noah is alive')
    
    # EDSA Signiture of secret key to produce public_key
    public_key2_point = Point.generate_publicKey(secret_key2)

    # Convert Public Key point on Elliptical curve to a bitcoin address (Public Identifier) using the SHA256 Encryption and RIPEMD-160 Encryption 
    bitcoin_address2 = PublicKey(public_key2_point).get_address( compressed = True)

    print(f"SECOND Secret key {secret_key2}, \n SECOND public key point {public_key2_point}, \n SECOND bitcoin address {bitcoin_address2}")
    

# Generating Transaction from Address 1 -> Address 2
    
    

    """
        - Instantiate history if Public key, by hard coding previous transaction key (https://blockstream.info/testnet/address/mqhVLUQz2PnyZUro9j33Z414Y8Q3UhSir6)
            - Reconstructs the key locking the UTXO
    """
    tx_in1  = TxIn(
    prev_tx = bytes.fromhex('d6c1e9e28a60e1bf41b2ef56ce68955c5df3a86d35fa90927cbeb05e1824db55'), # Previous Transaction id for origin public address, check blockstream.info
    prev_index = 0,
    script_sig = None, # this field will have the digital signature, to be inserted later
)
    public_key1_hash = PublicKey(public_key1_point).hash160_encoding(compressed = True)
    tx_in1.prev_tx_script_pubkey = Script([118, 169, public_key1_hash, 136, 172 ])




    tx_out = TxOut(
    amount = 1100, # we will send this 11000 sat to our target wallet, remainder will go to gas fees
    script_pubkey = None
)
    public_key2_hash = PublicKey(public_key2_point).hash160_encoding(compressed = True)
    tx_out.script_pubkey = Script([118, 169, public_key2_hash, 136, 172 ])
    # Generating Transaction script using the public Key hash, and requisite op-codes

    tx_out2 = TxOut(
    amount = 4500, # back to us
    script_pubkey= None
)
    tx_out2.script_pubkey = Script([118, 169, public_key1_hash, 136, 172 ])

    tx = Tx(
    version = 1,
    tx_ins = [tx_in1],
    tx_outs = [tx_out, tx_out2],
    )


    message= tx.encode(sig_index = 0 )
    import random
    from hashlib import sha256
    random.seed(int.from_bytes(sha256(message).digest(), 'big'))
    sig = sign(secret_key, message)
    sig_bytes_and_type1 = sig.encode() + b'\x01'
    public_key_bytes = PublicKey(public_key1_point).hash160_encoding(compressed = True, hash = False )
    tx_in1.script_sig = Script([sig_bytes_and_type1, public_key_bytes])
    print(tx.encode().hex())
    breakpoint()
