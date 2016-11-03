import hashlib, struct, base64

from pproxy.cipher import BaseCipher

# Pure Python Ciphers

class Table_Cipher(BaseCipher):
    LIBRARY = False
    KEY_LENGTH = 0
    IV_LENGTH = 0
    def setup(self):
        if self.key in self.CACHE:
            self.encrypt_table, self.decrypt_table = self.CACHE[self.key]
        else:
            a, _ = struct.unpack('<QQ', hashlib.md5(self.key).digest())
            table = list(range(256))
            for i in range(1, 1024):
                table.sort(key = lambda x: a % (x + i))
            self.encrypt_table = bytes(table)
            self.decrypt_table = bytes.maketrans(self.encrypt_table, bytes(range(256)))
            self.CACHE[self.key] = self.encrypt_table, self.decrypt_table
    def decrypt(self, s):
        return bytes.translate(s, self.decrypt_table)
    def encrypt(self, s):
        return bytes.translate(s, self.encrypt_table)

class StreamCipher(BaseCipher):
    LIBRARY = False
    def setup(self):
        self.stream = self.core()
    def encrypt(self, s):
        return bytes(i^next(self.stream) for i in s)
    decrypt = encrypt

class RC4_Cipher(StreamCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 0
    def core(self):
        data = list(range(256))
        y = 0
        for x in range(256):
            y = (self.key[x % self.KEY_LENGTH] + data[x] + y) & 0xff
            data[x], data[y] = data[y], data[x]
        x = y = 0
        while 1:
            x = (x+1) & 0xff
            y = (y+data[x]) & 0xff
            data[x], data[y] = data[y], data[x]
            yield data[(data[x]+data[y]) & 0xff]

class RC4_MD5_Cipher(RC4_Cipher):
    IV_LENGTH = 16
    def setup(self):
        self.key = hashlib.md5(self.key + self.iv).digest()
        RC4_Cipher.setup(self)

ROL = lambda a, b: a<<b|(a&0xffffffff)>>(32-b)
class ChaCha20_Cipher(StreamCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 8
    def core(self):
        data = list(struct.unpack('<16I', b'expand 32-byte k' + self.key + self.iv.rjust(16, b'\x00')))
        ORDERS = ((0,4,8,12),(1,5,9,13),(2,6,10,14),(3,7,11,15),(0,5,10,15),(1,6,11,12),(2,7,8,13),(3,4,9,14)) * 10
        while 1:
            H = data[:]
            for a, b, c, d in ORDERS:
                H[a] += H[b]
                H[d] = ROL(H[d]^H[a], 16)
                H[c] += H[d]
                H[b] = ROL(H[b]^H[c], 12)
                H[a] += H[b]
                H[d] = ROL(H[d]^H[a], 8)
                H[c] += H[d]
                H[b] = ROL(H[b]^H[c], 7)
            yield from struct.pack('<16I', *((a+b)&0xffffffff for a, b in zip(H, data)))
            data[12:14] = (0, data[13]+1) if data[12]==0xffffffff else (data[12]+1, data[13])

class ChaCha20_IETF_Cipher(ChaCha20_Cipher):
    IV_LENGTH = 12

class Salsa20_Cipher(StreamCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 8
    def core(self):
        data = list(struct.unpack('<16I', b'expa' + self.key[:16] + b'nd 3' + self.iv.ljust(16, b'\x00') + b'2-by' + self.key[16:] + b'te k'))
        ORDERS = ((4,0,12,8),(9,5,1,13),(14,10,6,2),(3,15,11,7),(1,0,3,2),(6,5,4,7),(11,10,9,8),(12,15,14,13)) * 10
        while 1:
            H = data[:]
            for a, b, c, d in ORDERS:
                H[a] ^= ROL(H[b]+H[c], 7)
                H[d] ^= ROL(H[a]+H[b], 9)
                H[c] ^= ROL(H[d]+H[a], 13)
                H[b] ^= ROL(H[c]+H[d], 18)
            yield from struct.pack('<16I', *((a+b)&0xffffffff for a, b in zip(H, data)))
            data[8:10] = (0, data[9]+1) if data[8]==0xffffffff else (data[8]+1, data[9])

class CFBCipher(StreamCipher):
    def setup(self):
        segment_bit = getattr(self, 'SEGMENT_SIZE', self.IV_LENGTH*8)
        self.bit_mode = segment_bit % 8 != 0
        self.stream = self.core_bit(segment_bit) if self.bit_mode else self.core(segment_bit//8)
        self.last = None
        self.cipher = self.CIPHER.new(self.key)
    def process(self, s, inv=False):
        r = bytearray()
        for i in s:
            if self.bit_mode:
                j = 0
                for k in range(7,-1,-1):
                    ibit = (i>>k)&1
                    jbit = ibit^self.stream.send(self.last)
                    j |= jbit<<k
                    self.last = ibit if inv else jbit
            else:
                j = i^self.stream.send(self.last)
                self.last = i if inv else j
            r.append(j)
        return bytes(r)
    def encrypt(self, s):
        return self.process(s, False)
    def decrypt(self, s):
        return self.process(s, True)
    def core(self, segment_byte):
        next_iv = bytearray(self.iv)
        while 1:
            data = self.cipher.encrypt(next_iv)
            del next_iv[:segment_byte]
            for i in range(segment_byte):
                next_iv.append((yield data[i]))
    def core_bit(self, segment_bit):
        next_iv = int.from_bytes(self.iv, 'big')
        mask = (1 << self.IV_LENGTH*8) - 1
        while 1:
            data = self.cipher.encrypt(next_iv.to_bytes(self.IV_LENGTH, 'big'))
            next_iv = next_iv<<segment_bit & mask
            for i in range(segment_bit):
                next_iv |= (yield (data[i//8]>>(7-i%8))&1)<<(segment_bit-1-i)

class CFB8Cipher(CFBCipher):
    SEGMENT_SIZE = 8

class CFB1Cipher(CFBCipher):
    SEGMENT_SIZE = 1

class CTRCipher(StreamCipher):
    def setup(self):
        self.stream = self.core()
        self.cipher = self.CIPHER.new(self.key)
    def encrypt(self, s):
        return bytes(i^next(self.stream) for i in s)
    decrypt = encrypt
    def core(self):
        next_iv = int.from_bytes(self.iv, 'big')
        while 1:
            yield from self.cipher.encrypt(next_iv.to_bytes(self.IV_LENGTH, 'big'))
            next_iv = 0 if next_iv >= (1<<(self.IV_LENGTH*8))-1 else next_iv+1

class OFBCipher(CTRCipher):
    def core(self):
        data = self.iv
        while 1:
            data = self.cipher.encrypt(data)
            yield from data

class RAW:
    CACHE = {}
    @classmethod
    def new(cls, key):
        if key in cls.CACHE:
            return cls.CACHE[key]
        ret = cls.CACHE[key] = cls(key)
        return ret

class AES(RAW):
    g1 = base64.b64decode(b'Y3x3e/Jrb8UwAWcr/terdsqCyX36WUfwrdSir5ykcsC3/ZMmNj/3zDSl5fFx2DEVBMcjwxiWBZoHEoDi6yeydQmDLBobblqgUjvWsynjL4RT0QDtIPyxW2rLvjlKTFjP0O+q+0NNM4VF+QJ/UDyfqFGjQI+SnTj1vLbaIRD/89LNDBPsX5dEF8Snfj1kXRlzYIFP3CIqkIhG7rgU3l4L2+AyOgpJBiRcwtOsYpGV5HnnyDdtjdVOqWxW9Opleq4IunglLhymtMbo3XQfS72LinA+tWZIA/YOYTVXuYbBHZ7h+JgRadmOlJseh+nOVSjfjKGJDb/mQmhBmS0PsFS7Fg==')
    g2 = [((a<<1)&0xff)^0x1b if a&0x80 else a<<1 for a in g1]
    g3 = [a^(((a<<1)&0xff)^0x1b if a&0x80 else a<<1) for a in g1]
    Rcon = base64.b64decode(b'jQECBAgQIECAGzZs2KtNmi9evGPGlzVq1LN9+u/FkTly5NO9YcKfJUqUM2bMgx06dOjL')
    shifts = tuple((j,j&3|((j>>2)+(j&3))*4&12,(j+3)&3|((j>>2)+((j+3)&3))*4&12,(j+2)&3|((j>>2)+((j+2)&3))*4&12,(j+1)&3|((j>>2)+((j+1)&3))*4&12) for j in range(16))
    def __init__(self, key):
        size, ekey = len(key), bytearray(key)
        nbr = {16:10, 24:12, 32:14}[size]
        while len(ekey) < 16*(nbr+1):
            t = ekey[-4:]
            if len(ekey) % size == 0:
                t = [self.g1[i] for i in t[1:]+t[:1]]
                t[0] ^= self.Rcon[len(ekey)//size%51]
            if size == 32 and len(ekey) % size == 16:
                t = [self.g1[i] for i in t]
            ekey.extend(m^ekey[i-size] for i, m in enumerate(t))
        self.ekey = tuple(ekey[i*16:i*16+16] for i in range(nbr+1))
    def encrypt(self, data):
        s = [data[j]^self.ekey[0][j] for j in range(16)]
        for key in self.ekey[1:-1]:
            s = [self.g2[s[a]]^self.g1[s[b]]^self.g1[s[c]]^self.g3[s[d]]^key[j] for j,a,b,c,d in self.shifts]
        return bytes(self.g1[s[self.shifts[j][1]]]^self.ekey[-1][j] for j in range(16))

for method in (CFBCipher, CFB8Cipher, CFB1Cipher, CTRCipher, OFBCipher):
    for key in (32, 24, 16):
        name = f'AES_{key*8}_{method.__name__[:-6]}_Cipher'
        globals()[name] = type(name, (method,), dict(KEY_LENGTH=key, IV_LENGTH=16, CIPHER=AES))

class Blowfish(RAW):
    P = None
    @staticmethod
    def hex_pi():
        N, n, d = 0, 0, 1
        for N in range(1<<20):
            xn, xd = 120*N**2 + 151*N + 47, 512*N**4 + 1024*N**3 + 712*N**2 + 194*N + 15
            n, d = ((16 * n * xd) + (xn * d)) % (d * xd), d * xd
            yield b'%x' % (16 * n // d)
    def __init__(self, key):
        if not self.P:
            pi = self.hex_pi()
            self.__class__.P = [int(b''.join(next(pi) for j in range(8)), 16) for i in range(18+1024)]
        self.p = [a^b for a, b in zip(self.P[:18], struct.unpack('>18I', (key*(72//len(key)+1))[:72]))]+self.P[18:]
        buf = b'\x00'*8
        for i in range(0, 1042, 2):
            buf = self.encrypt(buf)
            self.p[i:i+2] = struct.unpack('>II', buf)
    def encrypt(self, s):
        Xl, Xr = struct.unpack('>II', s)
        for i in range(16):
            Xl ^= self.p[i]
            y = ((self.p[18+(Xl>>24)]+self.p[274+((Xl>>16)&0xff)])^self.p[530+((Xl>>8)&0xff)])+self.p[786+(Xl&0xff)]
            Xl, Xr = (Xr ^ y) & 0xffffffff, Xl
        return struct.pack('>II', Xr^self.p[17], Xl^self.p[16])

class BF_CFB_Cipher(CFBCipher):
    KEY_LENGTH = 16
    IV_LENGTH = 8
    CIPHER = Blowfish

class Camellia(RAW):
    S1 = base64.b64decode(b'cIIs7LMnwOXkhVc16gyuQSPva5NFGaUh7Q5PTh1lkr2GuK+PfOsfzj4w3F9exQsapuE5ytVHXT3ZAVrWUVZsTYsNmmb7zLAtdBIrIPCxhJnfTMvCNH52BW23qTHRFwTXFFg6Yd4bERwyD5wWUxjyIv5Ez7LDtXqRJAjoqGD8aVCq0KB9oYlil1RbHpXg/2TSEMQASKP3dduKA+baCT/dlIdcgwLNSpAzc2f2851/v+JSm9gmyDfGO4GWb0sTvmMu6XmnjJ9uvI4p9fm2L/20WXiYBmrnRnG61CWrQoiijfpyB7lV+O6sCjZJKmg8OPGkQCjTe7vJQ8EV4630d8eAng==')
    S2, S3, S4 = bytes(i>>7|(i&0x7f)<<1 for i in S1), bytes(i>>1|(i&1)<<7 for i in S1), S1[::2]+S1[1::2]
    S = (S1, S4, S3, S2, S4, S3, S2, S1)
    KS = base64.b64decode(b'AAIICiAiKCpIShETGTM5OxIQQkBKSCMhKykAAgwOJCYoKkRGTE4RExkbMTM1Nz0/EhAaGEZESkgjIS8t')
    KS = tuple((i%16//4, i%4*32, (64,51,49,36,34)[i>>4]) for i in KS)
    def R(self, s, t):
        t = sum(S[((t^s>>64)>>(i*8))&0xff]<<(i*8+32)%64 for i,S in enumerate(self.S))
        t = t^t>>32<<8&0xffffff00^t>>56^((t>>32<<56|t>>8)^t<<48)&0xffff<<48^(t>>8^t<<16)&0xffff<<32
        return (t^t>>8&0xff<<24^t>>40^t<<16&0xff<<56^t<<56^(t>>32<<48^t>>16^t<<24)&0xffffff<<32^s)<<64&(1<<128)-1|s>>64
    def __init__(self, key):
        q, R = [int.from_bytes(key[:16], 'big'), int.from_bytes(key[16:], 'big'), 0, 0], self.R
        q[1] = q[1]<<64|q[1]^((1<<64)-1) if len(key)==24 else q[1]
        q[2] = R(R(R(R(q[0]^q[1],0xa09e667f3bcc908b),0xb67ae8584caa73b2)^q[0],0xc6ef372fe94f82be),0x54ff53a5f1d36f1c)
        q[3] = R(R(q[2]^q[1],0x10e527fade682d1d),0xb05688c2b3e6c1fd)
        nr, ks = (22, self.KS[:26]) if len(key)==16 else (29, self.KS[26:])
        e = [(q[n]<<m>>o|q[n]>>128-m+o)&(1<<64)-1 for n, m, o in ks]
        self.e = [e[i+i//7]<<64|e[i+i//7+1] if i%7==0 else e[i+i//7+1] for i in range(nr)]
    def encrypt(self, s):
        s = int.from_bytes(s, 'big')^self.e[0]
        for idx, k in enumerate(self.e[1:-1]):
            s = s^((s&k)>>95&0xfffffffe|(s&k)>>127)<<64^((s&k)<<1&~1<<96^(s&k)>>31^s<<32|k<<32)&0xffffffff<<96 ^ ((s|k)&0xffffffff)<<32^((s|k)<<1^s>>31)&k>>31&0xfffffffe^((s|k)>>31^s>>63)&k>>63&1 if (idx+1)%7==0 else self.R(s, k)
        return (s>>64^(s&(1<<64)-1)<<64^self.e[-1]).to_bytes(16, 'big')

class Camellia_256_CFB_Cipher(CFBCipher):
    KEY_LENGTH = 32
    IV_LENGTH = 16
    CIPHER = Camellia

class Camellia_192_CFB_Cipher(Camellia_256_CFB_Cipher):
    KEY_LENGTH = 24

class Camellia_128_CFB_Cipher(Camellia_256_CFB_Cipher):
    KEY_LENGTH = 16

MAP = {name[:-7].replace('_', '-').lower()+'-py': cls for name, cls in globals().items() if name.endswith('_Cipher')}

