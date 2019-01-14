import os, time, sys, pickle, os
from pproxy.cipher import MAP
from pproxy.cipherpy import MAP as MAP_PY

def test_both_cipher(A, B, size=4*1024, repeat=16):
    print('Testing', B.__name__, '...')
    t1 = t2 = 0
    for i in range(repeat):
        assert A.KEY_LENGTH == B.KEY_LENGTH and A.IV_LENGTH == B.IV_LENGTH
        key = os.urandom(A.KEY_LENGTH)
        iv = os.urandom(A.IV_LENGTH)
        t = time.perf_counter()
        a = A(key)
        a.setup_iv(iv)
        t1 += time.perf_counter() - t
        t = time.perf_counter()
        b = B(key)
        b.setup_iv(iv)
        t2 += time.perf_counter() - t
        s = os.urandom(size)
        t = time.perf_counter()
        s2 = a.encrypt(s)
        t1 += time.perf_counter() - t
        t = time.perf_counter()
        s3 = b.encrypt(s)
        t2 += time.perf_counter() - t
        assert s2 == s3

        t = time.perf_counter()
        a = A(key, True)
        a.setup_iv(iv)
        t1 += time.perf_counter() - t
        t = time.perf_counter()
        b = B(key, True)
        b.setup_iv(iv)
        t2 += time.perf_counter() - t
        t = time.perf_counter()
        s4 = a.decrypt(s2)
        t1 += time.perf_counter() - t
        t = time.perf_counter()
        s5 = b.decrypt(s2)
        t2 += time.perf_counter() - t
        assert s4 == s5 == s

    print('Passed', t1, t2)

def test_cipher(A, data, size=4*1024, repeat=16):
    if A.__name__ not in data:
        if input('Correct now? (Y/n)').upper() != 'Y':
            return
        d = []
        for i in range(repeat):
            key = os.urandom(A.KEY_LENGTH)
            iv = os.urandom(A.IV_LENGTH)
            a = A(key)
            a.setup_iv(iv)
            s = os.urandom(size)
            s2 = a.encrypt(s)
            a = A(key, True)
            a.setup_iv(iv)
            s4 = a.decrypt(s2)
            assert s == s4
            d.append((key, iv, s, s2))
        data[A.__name__] = d
        print('Saved correct data')
    else:
        t = time.perf_counter()
        print('Testing', A.__name__, '...')
        for key, iv, s, s2 in data[A.__name__]:
            a = A(key)
            a.setup_iv(iv)
            s3 = a.encrypt(s)
            assert s2 == s3
            a = A(key, True)
            a.setup_iv(iv)
            s4 = a.decrypt(s2)
            assert s == s4
        print('Passed', time.perf_counter()-t)


cipher = sys.argv[1] if len(sys.argv) > 1 else None
data = pickle.load(open('.cipherdata', 'rb')) if os.path.exists('.cipherdata') else {}

if cipher is None:
    print('Testing all ciphers')

    for cipher, B in sorted(MAP_PY.items()):
        A = MAP.get(cipher)
        if A:
            test_both_cipher(A, B)
        elif B.__name__ in data:
            test_cipher(B, data)
else:
    B = MAP_PY[cipher]
    A = MAP.get(cipher)
    if A:
        test_both_cipher(A, B)
    else:
        test_cipher(B, data)


pickle.dump(data, open('.cipherdata', 'wb'))

