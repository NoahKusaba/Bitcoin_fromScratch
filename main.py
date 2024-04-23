
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
    - We are going to create a transaction that sends funds from Account 1, where the remaining currency goes to gas fees:
        - 1100 Account 2
        - 4500 Account 1
    - Note that all the funds in a wallet needs to be spent, when sending from it, and remaining currency goes to gas fees. 
    - If gas fees too low it the transaction will not complete, or it will de deprioritized.
    
    - Funds for Account1 sourced from Test Net Faucet: https://coinfaucet.eu/en/btc-testnet/
    """

    public_key1_hash = PublicKey(public_key1_point).hash160_encoding(compressed = True)
    tx_in1  = TxIn(
    prev_tx = bytes.fromhex('d6c1e9e28a60e1bf41b2ef56ce68955c5df3a86d35fa90927cbeb05e1824db55'), # Previous Transaction id for origin public address, check blockstream.info
    prev_index = 0, # Instantiate history of Public key, by hard coding previous transaction key (https://blockstream.info/testnet/address/mqhVLUQz2PnyZUro9j33Z414Y8Q3UhSir6)
    secret_key = secret_key,
    public_key_hash = PublicKey(public_key1_point).hash160_encoding(compressed = True),
    public_key_bytes = PublicKey(public_key1_point).hash160_encoding(compressed = True, hash = False ),
    prev_tx_script_pubkey = Script([118, 169, public_key1_hash, 136, 172 ]), # Reconstructs the key locking the UTXO
    script_sig = None, # this field will have the digital signature, to be inserted later
    )

    tx_out = TxOut(
    amount = 1100, # we will send this 11000 sat to our target wallet, remainder will go to gas fees
    public_key_hash = PublicKey(public_key2_point).hash160_encoding(compressed = True),
    script_pubkey = None
)

    tx_out2 = TxOut(
    amount = 4500, # back to us
    public_key_hash = PublicKey(public_key1_point).hash160_encoding(compressed = True),
    script_pubkey= None
)

    tx = Tx(
    version = 1,
    tx_ins = [tx_in1],
    tx_outs = [tx_out, tx_out2],
    )
    print(f"""Generate Transaction Encoding  {tx.generate_encoding()} 
          Paste this into https://blockstream.info/testnet/tx/push to confirm transaction """)
    
    # See Account1 on Test net to view the completed Transaction: https://blockstream.info/testnet/address/mqhVLUQz2PnyZUro9j33Z414Y8Q3UhSir6


