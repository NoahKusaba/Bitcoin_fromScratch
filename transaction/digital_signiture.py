import random
from hashlib import sha256
from public_key.ecc import Point, origin_point
from dataclasses import dataclass 

"""
    - Generating valide signitures for transactions & Signing
         - This stuff is defined by bitcoin specifications.

"""



@dataclass
class Signature:
    r: int
    s: int

    """ return the DER encoding of this signature """
    def encode(self) -> bytes:

        def dern(n):
            nb = n.to_bytes(32, byteorder='big')
            nb = nb.lstrip(b'\x00') # strip leading zeros
            nb = (b'\x00' if nb[0] >= 0x80 else b'') + nb # preprend 0x00 if first byte >= 0x80
            return nb

        rb = dern(self.r)
        sb = dern(self.s)
        content = b''.join([bytes([0x02, len(rb)]), rb, bytes([0x02, len(sb)]), sb])
        frame = b''.join([bytes([0x30, len(content)]), content])
        return frame


def sign(secret_key: int, message: bytes) -> Signature:
    """
        - Method to sign transaction with private key to prove you are the owner of source wallet.
            - ECDSA specifications described in Specifications described in: https://en.bitcoin.it/wiki/Message_signing 
        - Check message against address to confirm. 
    """

    # Freezing to get consistent results when testing 
    random.seed(int.from_bytes(sha256(message).digest(), 'big')) 
    
    # the order of the elliptic curve used in bitcoin
    n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141

    z = int.from_bytes(sha256(sha256(message).digest()).digest(), 'big')

    # generate a new secret/public key pair at random
    sk = random.randrange(1, n)
    P = sk * origin_point

    # calculate the signature
    r = P.x
    s = int(Point.inverse(sk, n) * (z + secret_key * r) % n)

    if s > n / 2:
        s = n - s

    sig = Signature(r, s)
    return sig


