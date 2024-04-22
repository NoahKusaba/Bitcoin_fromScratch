
"""
Implementing Elliptical Curve Cryptography to generate public keys 
"""
from __future__ import annotations
from dataclasses import dataclass

"""
Characteristics of Elliptical Curve for Encryption:
    - Weistrass normal form
        - y^2 = x^3 + ax + b
    - Restricted to finite fields using modulo p
    - Based on description by Andrea Corbellini at https://andrea.corbellini.name/2015/05/17/elliptic-curve-cryptography-a-gentle-introduction/

Generate Public Key Point on Elliptical Curve by multiplying secret key by generator point
    - Multiplication occurs using the double & add algoirthm 
    - Double and add algorithm essentially just performs numerous algebraic additions for points on base elliptical cure. 
    - Need to ensure output is not 0 for security 

"""

@dataclass
class Curve:
    p: int 
    a: int
    b: int 

@dataclass
class Signature:
    r: int
    s: int

@dataclass
class Point:
    """
    Point on Elliptical Curve
    """

    curve: Curve
    x: int
    y:int

    @classmethod
    def inverse(self, n, p):
        """ 
            - Get Inverse of variables using extended_euclidean algorithm:
                - Returns (greatest common denominator, x, y) a * x + b * y == gcd(a,b)
                    - O log (b) algorithm 
            - returns modular multiplicate inverse (n * m) % p == 1 
        """

        gcd, r = n, p
        x, s = 1, 0
        y, t = 0, 1
        while r != 0:
            quotient = gcd // r
            gcd, r = r, gcd - quotient * r
            x, s = s, x - quotient * s
            y, t = t, y - quotient * t

        return x % p
    
    # Algebraic addition
    def __add__(self, other:Point) -> Point:

        if self == INF: return other
        if other == INF: return self 
        if self.x == other.x and self.y != other.y:return INF

        if self.x == other.x: 
            m = (3 * self.x**2 + self.curve.a) * self.inverse(2 * self.y, self.curve.p)
        else: 
            m = (self.y - other.y ) * self.inverse(self.x - other.x, self.curve.p)

        xr = (m**2  - self.x - other.x) %  self.curve.p
        yr = (-(self.y + m * (xr - self.x ))) %  self.curve.p

        return Point(self.curve, xr, yr)

    #Double and Add Algorithm
    def __rmul__(self, n: int) -> Point:
        result = INF
        addend = self
        while n:
            if n & 1 : 
                result += addend 
            addend += addend
            n >>= 1 
        return result 
    
    @classmethod
    def generate_publicKey(self, secret_key):
        # Essentially multiplies as x * y = y + y + y, ... yx
        public_key = secret_key * origin_point
        # Check that public key is on curve
        assert (public_key.y**2 - public_key.x**3 - 7) % bitcoin_curve.p == 0, "Public Key Algorithm is Broken"
        return public_key
    
    def sign(self,secret_key, message):
        import random
        from hashlib import sha256
        n = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141
        z = int.from_bytes(sha256(sha256(message)), 'big')
        sk = random.randrange(1, n)
        P = sk * origin_point

        # calculate the signature
        r = P.x
        s = self.inv(sk, n) * (z + secret_key * r) % n
        if s > n / 2:
            s = n - s

        sig = Signature(r, s)
        return sig

INF = Point(None, None, None) # Infinity Point

bitcoin_curve = Curve(
    p = 0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFC2F,
    a = 0x0000000000000000000000000000000000000000000000000000000000000000, # a = 0
    b = 0x0000000000000000000000000000000000000000000000000000000000000007, # b = 7
)

# Origin point/Generator point existing on Bitcoin Curve
origin_point = Point(
    bitcoin_curve,
    x = 0x79BE667EF9DCBBAC55A06295CE870B07029BFCDB2DCE28D959F2815B16F81798,
    y = 0x483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8, 
)