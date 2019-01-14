import os, time
from pproxy.cipher import AES_256_CFB_Cipher as A
from pproxy.cipherpy import AES_256_CFB_Cipher as B
from pproxy.cipher import ChaCha20_Cipher as C
from pproxy.cipherpy import ChaCha20_Cipher as D
from pproxy.cipherpy import Camellia_256_CFB_Cipher as E

TO_TEST = (A, B, C, D, E)

for X in TO_TEST:
    t = time.perf_counter()
    for i in range(10):
        c = X(os.urandom(X.KEY_LENGTH))
        c.setup_iv()
        for j in range(100):
            c.encrypt(os.urandom(1024))
    print(time.perf_counter()-t)
