import hashlib # I am not hand coding this
# Encodings used Sha256, Ripemd160, B58Encoding

class PublicKey():
    """
    - Generating Public Address from EDSA signiture
        - Standard defined by: https://en.bitcoin.it/wiki/Invoice_address
    """
    def __init__(self, point):
        self.x = point.x
        self.y = point.y
        self.curve = point.curve

    def hash160_encoding(self, compressed = False, hash = True):
        """
        - Encoding Public Key using both SHA256 & RIPEMD-160
            - Stacking both hashes:
                - Lowers probability of collission and unexpected interactions with ECDSA: 
                - Prevents Length Extension attacks.
                    - https://bitcoin.stackexchange.com/questions/9202/why-does-bitcoin-use-two-hash-functions-sha-256-and-ripemd-160-to-create-an-ad
                    - https://medium.com/asecuritysite-when-bob-met-alice/ripemd160-f28062242045
            - SHA256:
                - 256 bit hash
            - RIPMD-160:
                - Shortest hash with sufficient uniqueness. 
                - 160 bit hash
        """
    
        """
        - Compressing key to reduce space
            - Derive y from y^2 = x^3 + 7, as y = +/- sqrt(x^3 + 7)
            - "x0_" + x
        - Denote with:
            - "x02" for positive y
            - "x03" for negative y
        - Uncompressed is:
            - "x04" + x + y 
        """ 
        if compressed: 
            prefix = b'\x02' if self.y % 2 == 0 else b'\x03'
            key_bytes = prefix + self.x.to_bytes(32,"big")  # Set to positive y 
        else: key_bytes = b'\x04' + self.x.to_bytes(32,"big") + self.y.to_bytes(32, "big")
        return hashlib.new("ripemd160", hashlib.sha256(key_bytes).digest()).digest()  if hash else key_bytes
    

    # Checksum of the public_key hash, algorithm is sha256(sha256(key)), aka hash256
   
    def hash256_checksum(self, public_key_hash): return hashlib.sha256(hashlib.sha256(public_key_hash).digest()).digest()

    def b58_encoding(self, b:bytes):

        """
            B58 Encoding
                - Encodes bytes using base 58 
                - Different Prefix byte depending on Main-net or Test-net 
                - Outputs a 25 byte address
                - Reference: https://en.bitcoin.it/wiki/Base58Check_encoding
        """
        # 1 Byte version + 20 Bytes hash + 4 Bytes checksum
        code_string = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
        assert len(b) == 25

        b58_encoding = int.from_bytes(b,"big")
        output_encoding = ""

        while b58_encoding: 
            b58_encoding, r = divmod(b58_encoding, 58)
            output_encoding += code_string[r]

        # Handle Leading zeroes , by replacng with 1 and reversing encoding
        num_leading_zeroes = len(b) - len(b.lstrip(b'\x00'))
        return num_leading_zeroes * code_string[0] +  output_encoding[::-1]
    
    def get_address(self, net = "test", compressed = True):
        public_key_hash = self.hash160_encoding( compressed= compressed)

        # Main Net and test Net denoted by different prefixes. 
        net_version = {'main': b'\x00', 'test': b'\x6f'}

        net_pk_hash = net_version[net] + public_key_hash

        checksum = self.hash256_checksum(net_pk_hash)[:4]

        net_pk_hash_checksum = net_pk_hash + checksum

        return self.b58_encoding(net_pk_hash_checksum)
