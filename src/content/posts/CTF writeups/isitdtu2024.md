---
title: ISITDTU CTF 2024
published: 2024-10-27
description: ''
image: '../logo/isitdtu.png'
tags: [agcd, root of unity]
category: 'CTF Writeups'
draft: false 
---
# ISITDTU CTF 2024

> This is my write-up for 3 challenges in crypto category I solved in ISITDTU CTF 2024. 2 unsolved challenges may be updated in the future 🤔. Thanks to all authors for very nice challenges 😁

## ShareMixer1
```py
import random   # TODO: heard that this is unsafe but nvm
from Crypto.Util.number import getPrime, bytes_to_long
flag = bytes_to_long(b'ISITDTU{test_flag_dkosakdisaj}')
# flag = bytes_to_long(open("flag.txt", "rb").read())
p = getPrime(256)
assert flag < p
l = 32


def share_mixer(xs):
    cs = [random.randint(1, p - 1) for _ in range(l - 1)]
    cs.append(flag)

    # mixy mix
    random.shuffle(xs)
    random.shuffle(cs)

    shares = [sum((c * pow(x, i, p)) % p for i, c in enumerate(cs)) % p for x in xs]
    return shares


if __name__ == "__main__":
    try:
        print(f"{p = }")
        queries = input("Gib me the queries: ")
        xs = list(map(lambda x: int(x) % p, queries.split()))

        if 0 in xs or len(xs) > 256:
            print("GUH")
            exit(1)

        shares = share_mixer(xs)
        print(f"{shares = }")
    except:
        exit(1)
```
- This challenge, we are asked to give a "query" containing a list of integers `xs`, which its length must be less or equal than 256 and it doesn't contain 0 (mod p) element. Then the server will calculate $f(x)$ with random coefficients (one of them is flag) with $x$ in `xs`. The output is shuffled before giving to us.
- Because the output is shuffled, we can not differentiate which value of $f(x)$ belongs to $x$. So we have to do a trick: Sending a sequence of value like $1, 2, 2, 3, 3, 3, ...,n,...,n$, then we based on the frequency of occurrence of elements to determine which value of $f(x)$ belongs to $x$. Then solve a system of equations to find flag.
- To be able to solve the system of equations, we have to have enough 32 value of $f(x)$, which means we need 32 value of $x$. But we can recognize that with this method of building the query, its length is too large. So we have another option to build this:
    - With i from 1 to 15: `payload += [xs[i]] * i`
    - With i from 16 to 30: `payload += [xs[i]]*(i-15)`
    - `payload += [xs[31]]`
    - `payload += 2*[xs[32]]`
```python 
xs = [random.randint(0,p) for i in range(33)]

payload = []
for i in range(1,16):
    payload += [xs[i]] * i 
for i in range(16,31):
    payload += [xs[i]]*(i-15)
payload += [xs[31]]
payload += 2*[xs[32]]
payload = ' '.join(str(i) for i in payload)
```
- After having the outputs, we have to brute all case of permutations (totally $3!*3!*2^{13}$), it's feasible to brute-force.
- Solve script: 
```python=
from pwn import * 
from itertools import permutations
from sage.all import * 
from Crypto.Util.number import *
from tqdm import *
from collections import Counter
import random
io = process(["python3", "chall.py"])
# io = remote("35.187.238.100", 5001)

def find(n, ctr):
	return [element for element, count in ctr.items() if count == n]


def combine(arr):
    perms = [list(permutations(x)) for x in arr]
    
    result = [[]]
    for options in perms:
        result = [x + list(y) for x in result for y in options]
    
    return result
p = int(io.recvlineS().strip().split()[2])
print(p)
xs = [random.randint(0,p) for i in range(33)]

payload = []
for i in range(1,16):
    payload += [xs[i]] * i 
for i in range(16,31):
    payload += [xs[i]]*(i-15)
payload += [xs[31]]
payload += 2*[xs[32]]
payload = ' '.join(str(i) for i in payload)

io.sendlineafter(b'Gib me the queries: ', payload.encode())

shares = eval(io.recvlineS().strip().split('=')[1])
ctr = Counter(shares)
res = []
for i in range(1, 16):
    res.append(find(i, ctr))

candidate = combine(res)
F = GF(p)
mtx = []
x = [xs[1], xs[16],xs[31],xs[2],xs[17],xs[32]]
for i in range(3, 16):
    x += [xs[i], xs[i + 15]]
assert len(x) == 32
for i in x:
	row = []
	for j in range(32):
		row.append(pow(i,j,p))
	mtx.append(row)
# print(mtx)
mtx = Matrix(GF(p), mtx)
inv = ~mtx
for arr in tqdm(candidate):	
	# print(res)
	x = inv * vector(F, arr)
	x = [long_to_bytes(int(i)) for i in x]
	for i in x:
		if b'ISITDTU' in i:
			print(i)
			quit()
```

![image](https://hackmd.io/_uploads/SkzngTsxJg.png)

## ShareMixer2

```python=
import random   # TODO: heard that this is unsafe but nvm
from Crypto.Util.number import getPrime, bytes_to_long
flag = bytes_to_long(b'ISITDTU{test_flag_dkosakdisaj}')

# flag = bytes_to_long(open("flag.txt", "rb").read())
# p = getPrime(256)
p = 113862595042194342666713652805343274098934957931279886727932125362984509580161
assert flag < p
l = 32

def share_mixer(xs):
    cs = [random.randint(1, p - 1) for _ in range(l - 1)]
    cs.append(flag)

    # mixy mix
    random.shuffle(xs)
    random.shuffle(cs)
    print(cs[0])
    shares = [sum((c * pow(x, i, p)) % p for i, c in enumerate(cs)) % p for x in xs]
    return shares


if __name__ == "__main__":
    try:
        print(f"{p = }")
        queries = input("Gib me the queries: ")
        xs = list(map(lambda x: int(x) % p, queries.split()))

        if 0 in xs or len(xs) > 32:
            print("GUH")
            exit(1)

        shares = share_mixer(xs)
        print(f"{shares = }")
    except:
        exit(1)
```
- This challenge, the author limits the length of query to 32, exactly equal to the number of values we need. 
- After thinking a while, I realize that if we send -1 and 1 to get $f(1)$ and $f(-1)$, we can calculate $\sum_{i=2k}c_i*x^i = \frac{f(-1) +f(1)}{2}$, note that $-1$ and $1$ are the 2nd roots of unity in `GF(p)`. If we send 4th-roots of unity, we can see that $\sum_{i=4k}^{}c_i*x^i = \frac{f(x_1) +f(x_2) + f(x_3)+f(x_4)}{4}$
- Therefore, my idea is sending 32nd-roots of unity in `GF(p)`, with the condition that $p-1$ must be divisible by 32. Then we calculate the value of $\frac{1}{32}\sum_{}^{}f(x_i)$ and "hope" that the flag is $c_0$.
- Solve script:
```python
from pwn import * 
from sage.all import * 
from Crypto.Util.number import *
while True:
    io = remote("35.187.238.100", 5002)
    p = int(io.recvlineS().strip().split()[2])
    if (p-1)%32 != 0:
        io.close()
        continue
    g = int(GF(p).multiplicative_generator())
    g = pow(g, (p-1)//32, p)
    xs = [pow(g, i, p) for i in range(32)]
    payload = ' '.join(str(i) for i in xs)
    io.sendlineafter(b'Gib me the queries: ', payload.encode())
    shares = eval(io.recvlineS().strip().split('=')[1])

    flag = long_to_bytes(sum(shares) * pow(32, -1, p) % p)
    if b'ISITDTU' in flag:
        print(flag)
        quit()
# ISITDTU{M1x_4941n!_73360d0e5fb4}  
```
> Because the author doesn't put PoW on server, we can easily "gacha" this.

## Sign
```python=
#!/usr/bin/env python3

import os

from Crypto.Util.number import *
from Crypto.Signature import PKCS1_v1_5
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256

flag = b'ISITDTU{aaaaaaaaaaaaaaaaaaaaaaaaaa}'
flag = os.urandom(255 - len(flag)) + flag


def genkey(e=11):
    while True:
        p = getPrime(1024)
        q = getPrime(1024)
        if GCD(p-1, e) == 1 and GCD(q-1, e) == 1:
            break
    n = p*q
    d = pow(e, -1, (p-1)*(q-1))
    return RSA.construct((n, e, d))


def gensig(key: RSA.RsaKey) -> bytes:
    m = os.urandom(256)
    h = SHA256.new(m)
    s = PKCS1_v1_5.new(key).sign(h)
    ss = bytes_to_long(s)

    return s


def getflagsig(key: RSA.RsaKey) -> bytes:
    return long_to_bytes(pow(bytes_to_long(flag), key.d, key.n))


key = genkey()

while True:
    print(
        """=================
1. Generate random signature
2. Get flag signature
================="""
    )

    try:
        choice = int(input('> '))
        if choice == 1:
            sig = gensig(key)
            print('sig =', sig.hex())
        elif choice == 2:
            sig = getflagsig(key)
            print('sig =', sig.hex())
    except Exception as e:
        print('huh')
        exit(-1)
```
- In this challenge, the server allows us to sign a random message or sign flag with unlimited times. It uses the `PKCS1_v1_5` algorithm to sign. Its python implementation in pycryptodome module is [here](https://github.com/Legrandin/pycryptodome/blob/dc92e70ffb276d946364f62d0f87c6d66d75ffe3/lib/Crypto/Signature/pkcs1_15.py#L35)
- Before RSA decryption, the hashed message is encoded by `_EMSA_PKCS1_V1_5_ENCODE` function, which will add a fixed padding for a type of hash algorithm. With `SHA256` hash algorithm, we can see this padding is:
```python 
prefix = b'\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 '
```
> This padding can be easily found with this [code](https://github.com/ashutosh1206/Crypton/blob/master/Digital-Signatures/PKCS%231-v1.5-Padded-RSA-Digital-Signature/example.py)
- We can see that: `prefix + msg + k*n = sig^e` with `e=11`, so small :v. Note that we can submit to server unlimited time, we can request more random signatures to construct more functions, then use AGCD (Approximate gcd) to find `n`, then we can easily recover flag. 
- Solve script: 
```python=
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Util.number import *
from Crypto.Hash import *
from pwn import *
import sys
sys.path.append("/mnt/e/tvdat20004/CTF/tools/attacks/acd/")
from ol import * 
io = remote("35.187.238.100", 5003)
io.recvuntil(b'Suffix: ')
poW = input("cccc: ")
io.sendline(poW.encode())
# io = process(["python3", "chall.py"])
def random_sign():
	io.sendlineafter(b'> ', b'1')
	return int(io.recvlineS().strip().split(' ')[2], 16)

prefix = b'\x01\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\x00010\r\x06\t`\x86H\x01e\x03\x04\x02\x01\x05\x00\x04 '
pre = bytes_to_long(prefix) * 2**256 
xs = [(random_sign()**11 - pre) for _ in range(30)]
# print(xs)

n = attack(xs, 256)[0]
io.sendlineafter(b'> ', b'2')
enc = int(io.recvlineS().strip().split(' ')[2], 16)
print(long_to_bytes(pow(enc, 11, n)))
```
> `attack` function is from [here](https://github.com/jvdsn/crypto-attacks/blob/master/attacks/acd/ol.py)
> 
![image](https://hackmd.io/_uploads/B1s5TTjxkx.png)
