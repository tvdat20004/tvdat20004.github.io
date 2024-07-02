---
title: Google CTF 2024
published: 2024-06-29
description: "Google CTF 2024"
image: "../logo/flag_logo.gif"
tags: [Triple DES, ECC, Mceliece cryptosystem, error correcting code]
category: CTF Writeups
draft: false
---
# Google CTF 2024
> Tuần vừa rồi, mình có chơi googleCTF cùng các anh trong team **CosGang** và được hạng 28. Bản thân mình cũng "may mắn" giải được 3 bài (thực ra bài đầu mình choke quá nên người thực sự solve là anh @vnc :<). Sau đây là chi tiết cách làm của mình.

![image](https://hackmd.io/_uploads/H1f3yr2I0.png)

## DESFUNCTIONAL - 112 solves
![image](https://hackmd.io/_uploads/HkbggSn8A.png)
- chall.py
```python=
import signal
import os
import random
import sys
from Crypto.Cipher import DES3


class Desfunctional:
    def __init__(self):
        self.key = os.urandom(24)
        self.iv = os.urandom(8)
        self.flipped_bits = set(range(0, 192, 8))
        self.challenge = os.urandom(64)
        print(self.challenge.hex())
        self.counter = 128

    def get_flag(self, plain):
        if plain == self.challenge:
            
            return "hahahaha"
        raise Exception("Not quite right")

    def get_challenge(self):
        cipher = DES3.new(self.key, mode=DES3.MODE_CBC, iv=self.iv)
        return cipher.encrypt(self.challenge)

    def corruption(self):
        if len(self.flipped_bits) == 192:
            self.flipped_bits = set(range(0, 192, 8))
        remaining = list(set(range(192)) - self.flipped_bits)
        num_flips = random.randint(1, len(remaining))
        self.flipped_bits = self.flipped_bits.union(
            random.choices(remaining, k=num_flips))
        mask = int.to_bytes(sum(2**i for i in self.flipped_bits), 24, "big")
        return bytes(i ^ j for i, j in zip(self.key, mask))

    def decrypt(self, text: bytes):
        self.counter -= 1
        if self.counter < 0:
            raise Exception("Out of balance")
        key = self.corruption()
        if len(text) % 8 != 0:
            return b''
        cipher = DES3.new(key, mode=DES3.MODE_CBC, iv=self.iv)
        return cipher.decrypt(text)


if __name__ == "__main__":
    chall = Desfunctional()
    PROMPT = ("Choose an API option\n"
              "1. Get challenge\n"
              "2. Decrypt\n"
              "3. Get the flag\n")
    signal.alarm(128)
    while True:
        try:
            option = int(input(PROMPT))
            if option == 1:
                print(chall.get_challenge().hex())
            elif option == 2:
                ct = bytes.fromhex(input("(hex) ct: "))
                print(chall.decrypt(ct).hex())
            elif option == 3:
                pt = bytes.fromhex(input("(hex) pt: "))
                print(chall.get_flag(pt))
                sys.exit(0)
        except Exception as e:
            print(e)
            sys.exit(1)

```
- Đề này cho ta một server cho ta các chức năng để làm việc với class `Desfunctional` mà họ định nghĩa, dựa trên hệ mã [triple DES](https://en.wikipedia.org/wiki/Triple_DES). 
- Server cho ta 3 option như trên code:
    - Option 1 cho phép ta lấy encrypted `challenge` với challenge là chuỗi 64 byte ngẫu nhiên. 
![image](https://hackmd.io/_uploads/ryd8HH2IR.png)
    - Option 2: Decrypt plaintext mà người dùng nhập vào, tuy nhiên trước khi decrypt, nó sẽ flip một vài bit của key (việc chọn các bit để flip là hoàn toàn random). Ta chỉ được 128 lần sử dụng option này.
![image](https://hackmd.io/_uploads/HynCSH2UC.png)
    - Option 3: Đoán giá trị của `challenge` để lấy flag.
- Để ý ở option 2, sau mỗi lần decrypt, mảng `self.flipped_bits` (vị trí các bit cần flip) không được reset. Nó chỉ được reset khi `len` của nó dài 192 (bằng độ dài key). Thêm vào đó sau một hồi research thì mình tìm thấy một [tính chất](https://en.wikipedia.org/wiki/Data_Encryption_Standard#Minor_cryptanalytic_properties) khá ảo ma của DES (và cũng đúng với triple DES):
![image](https://hackmd.io/_uploads/rJyour3IR.png)
- Lợi dụng tính chất đó, ta có thể request liên tiếp option 2 với giá trị `ct = ~(encrypted_challenge)`, đến khi nào các bit của key bị flip hết thì ta thu được giá trị `dec`. Ta tìm lại `challenge` bằng cách đảo bit thuộc block đầu của dec, các block sau giữ nguyên. Điều này là do nó decrypt theo mode CBC, các block sau sẽ được triệt tiêu phép đảo bit qua các phép XOR.
![image](https://hackmd.io/_uploads/rJAteLhI0.png)
- solve.py (author: @vnc)
```python=
from pwn import *
from tqdm import tqdm
from Crypto.Util.number import *
from collections import Counter

def get_challenge():
    io.sendlineafter(b"flag\n", b"1")
    return bytes.fromhex(io.recvline().strip().decode())

def decrypt(ct):
    io.sendlineafter(b"flag\n", b"2")
    io.sendlineafter(b"(hex) ct: ", ct.hex().encode())
    return bytes.fromhex(io.recvline().strip().decode())

def bitwise_complement(x, nbits=64):
    return x ^ (2**nbits - 1)

if __name__ == "__main__":
    io = remote("desfunctional.2024.ctfcompetition.com", 1337)

    enc  = get_challenge()
    decs = []
    for _ in tqdm(range(128)):
        x = decrypt(long_to_bytes(bitwise_complement(bytes_to_long(enc), 64*8)))
        decs.append(x)
    
    ctr  = Counter(decs)
    cc   = ctr.most_common(1)[0][0]
    ans  = long_to_bytes(bitwise_complement(bytes_to_long(cc[:8]))) + cc[8:]

    io.sendlineafter(b"flag\n", b"3")
    io.sendlineafter(b"pt: ", ans.hex().encode())
    io.interactive()
```
![image](https://hackmd.io/_uploads/Hku0m8280.png)

## BLINDERS - 56 solves
![image](https://hackmd.io/_uploads/BkLlEU2IC.png)
- chall.py
```python=
from ecdsa.curves import NIST256p
from ecdsa.numbertheory import jacobi, square_root_mod_prime
from ecdsa.ellipticcurve import Point
from Crypto.Random import random
import hashlib

curve = NIST256p.curve

def H(id):
    a, b, p = curve.a(), curve.b(), curve.p()

    hash = hashlib.sha256(f'id={id}'.encode()).digest()
    x = int.from_bytes(hash, 'big')

    while True:
        y2 = (x**3 + a*x + b) % p
        if jacobi(y2, p) == 1: break
        x += 1

    y = square_root_mod_prime(y2, p)
    return Point(curve, x, y)

# Implements Blinders, a private set membership protocol.
class BlindersServer:
    def __init__(self, S):
        self.S = S
    
    def handle(self, client_eid):
        # 2.1. Generate a random secret key k
        k = random.randrange(0, int(NIST256p.order))
        # k = 10
        # Compute eid1 = H(id1)^K, ..., eidn = H(idn)^K
        eids = [H(id) * k for id in self.S]
        # Compute doubly-encrypted identifier deid = eid^K
        deid = client_eid * k
        # Return (eid1, ..., eidn) and deid to P1
        return eids, deid

def challenge():
    # S = {0, 1, ..., 255} \ {x} for some 0 <= x < 256
    S = list(range(256))
    x = random.getrandbits(8)
    
    S.remove(x)
    server = BlindersServer(S)

    for _ in range(3):
        operation, *params = input().split()
        if operation == 'handle':
            client_eid = Point(curve, int(params[0]), int(params[1]))
            eids, deid = server.handle(client_eid)
            print([(eid.x(), eid.y()) for eid in eids])
            print((deid.x(), deid.y()))
        elif operation == 'submit':
            client_S_hash = bytes.fromhex(params[0])
            S_hash = hashlib.sha256(','.join(map(str, server.S)).encode()).digest()
            return client_S_hash == S_hash
        else:
            return False

if __name__ == '__main__':
    FLAG = b'TEST_FLAG'
    print(1)
    # Convince me 16 times and I will give you the flag :)
    for _ in range(16):
        if challenge():
            print('OK!')
        else:
            print('Nope.')
            break
    else:
        print(FLAG)
```
- Giống như description nói, bài này ta phải đoán server bỏ đi số nào trong list từ 0 đến 255 (các số này trong bài gọi là các id). Server bài này cho ta 2 option:
    - Option `handle` cho phép ta gởi 1 điểm lên server, sau đó server gởi lại k (random) nhân với điểm mình gởi, cùng với đó là các `H(id) * k`.
    ![image](https://hackmd.io/_uploads/SJ4gK8hL0.png)
    ![image](https://hackmd.io/_uploads/BkjmD8nLA.png)
    - Option `submit` để ta check kết quả, đoán đúng số bị remove thì sẽ được pass.
- Bài này tốn mình kha khá thời gian để tìm cách gởi điểm như thế nào, vì nó chỉ cho phép gởi tối đa 2 request handle. Idea mình dùng ở đây là gởi chẵn lẻ, tức là lần 1 mình gởi điểm là tổng các `H(id)` với id chẵn, giả sử nhận về `eid1` và `d_even`; lần 2 là gởi với các id lẻ, nhận về `eid2` và `d_odd`. 
- Với các dữ kiện đã thu được, ta tính được giá trị `k*H(id)` bị miss bằng cách:
```python=
n = 256
id_points = [H(id) for id in range(n)]
eids_even = sum(id_points[::2])
eids_odd = sum(id_points[1::2])    
eid1, d_even = handle(*eids_even.xy())
eid2, d_odd = handle(*eids_odd.xy())
value1 = d_even + d_odd - sum(eid1)
value2 = d_even + d_odd - sum(eid2)
```
- Tiếp theo thì ta brute vị trí cho nó bằng cách thêm nó vào các chuỗi `eid` lần lượt ở các vị trí từ 0 đến 255. Sau đó check điều kiện tổng chẵn và tổng lẻ của chuỗi thu được có bằng `d_even` và `d_odd` không, nếu bằng thì chắc chắn đó là vị trí cần tìm => problem solved.
```python=
full1 = eid1[:i] + [value1] + eid1[i:]
full2 = eid2[:i] + [value2] + eid2[i:]
if (sum(full1[::2]) == d_even and sum(full1[1::2]) == d_odd) or (sum(full2[::2]) == d_even and sum(full2[1::2]) == d_odd):
	print(i)
	arr = list(range(n))
	arr.remove(i)
	submit(arr)
	break
```
- Full script:
```python=
from ecdsa import numbertheory 
from sage.all import *
from Crypto.Random import random
import hashlib
import ast
from pwn import *
p = 0xffffffff00000001000000000000000000000000ffffffffffffffffffffffff
K = GF(p)
a = K(0xffffffff00000001000000000000000000000000fffffffffffffffffffffffc)
b = K(0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b)
E = EllipticCurve(K, (a, b))
def H(id):
	hash = hashlib.sha256(f'id={id}'.encode()).digest()
	x = int.from_bytes(hash, 'big')

	while True:
		y2 = (x**3 + a*x + b) % p
		if numbertheory.jacobi(int(y2), p) == 1:
			break
		x += 1
	y = numbertheory.square_root_mod_prime(int(y2), p)
	return E(x, y)
	
r = remote("blinders.2024.ctfcompetition.com" ,1337)
# r = process(["python3", "chall.py"])

def handle(x,y):
	payload = f"handle {x} {y}"
	r.sendline(payload.encode())
	eids = eval(r.recvlineS().strip())
	deid = eval(r.recvlineS().strip())
	# eids = eval(r.recvlineS().strip().replace("mpz", ""))
	# deid = eval(r.recvlineS().strip().replace("mpz", ""))
	return [E(*eid) for eid in eids], E(*deid)

def submit(S):
	hash = hashlib.sha256(','.join(map(str, S)).encode()).hexdigest()
	r.sendline(f'submit {hash}'.encode())
	return r.recvlineS()

print(r.recvlineS())
n = 256
id_points = [H(id) for id in range(n)]
# ss = [i * 10 for i in id_points]
eids_even = sum(id_points[::2])
eids_odd = sum(id_points[1::2])
for i in range(16):
	eid1, d_even = handle(*eids_even.xy())
	eid2, d_odd = handle(*eids_odd.xy())
	value1 = d_even + d_odd - sum(eid1)
	value2 = d_even + d_odd - sum(eid2)
	for i in range(n):
		full1 = eid1[:i] + [value1] + eid1[i:]
		full2 = eid2[:i] + [value2] + eid2[i:]

		if (sum(full1[::2]) == d_even and sum(full1[1::2]) == d_odd) or (sum(full2[::2]) == d_even and sum(full2[1::2]) == d_odd):
			print(i)
			arr = list(range(n))
			arr.remove(i)
			submit(arr)
			break
r.interactive()
```
![image](https://hackmd.io/_uploads/BkNYIwnIC.png)
## MCELIECE - 12 solves

![image](https://hackmd.io/_uploads/BJULwDhUR.png)

- chall.sage
```python=
def gen_pubkey(p, n, k, r):
    F = GF(p)
    assert p > n, "Number of elements in field should be greater than n"
    C = codes.GeneralizedReedSolomonCode(sample(F.list(), n), k)
    S = matrix(F, k, k)
    S.randomize()
    while S.rank() != k:
        S.randomize()
    G = C.generator_matrix()
    R = matrix(k, r, lambda i, j: F.random_element())
    Q = list(identity_matrix(n + r))
    shuffle(Q)
    Q = matrix(F, Q)
    G_pub = S.inverse() * G.augment(R) * Q.inverse()
    pubkey = G_pub
    privkey = (C, S, Q)
    return (pubkey, privkey)


def encode_message(message: bytes, F, k):
    p = F.cardinality()
    message_int = int.from_bytes(message, 'big')
    message_vector = []
    while message_int:
        message_vector.append(message_int % p)
        message_int //= p
    print(len(message_vector))
    padding = k - len(message_vector) % k
    message_vector += [padding] * padding
    return [vector(F, message_vector[i:i + k])
            for i in range(0, len(message_vector), k)]


def encrypt(message: bytes, pubkey):
    k, n = pubkey.dimensions()
    F = pubkey[0, 0].parent()
    num_errors = (n - k) // 4 # 21
    encryptions = []
    for m in encode_message(message, F, k):
        print(m)
        error = [F.random_element() for _ in range(num_errors)] + \
            [0] * (n - num_errors)
        shuffle(error)
        error = vector(F, error)
        encryptions.append(m * pubkey + error)
    return encryptions


def main(p, n, k, r):
    pubkey, privkey = gen_pubkey(p, n, k, r)
    FLAG = b"CTF{test_flag_iwiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiiii}"

    encrypted_flag = encrypt(FLAG, pubkey)
    pubkey.dump("pubkey.sobj")
    matrix(encrypted_flag).dump("flag_enc.sobj")

if __name__ == "__main__" and "__file__" in globals():
    p, n, k, r = 521, 256, 169, 39
    main(p, n, k, r)
```
- Như description có nói, bài này cần có Sagemath >= 9.7 mới parse được file key. Mình mất kha khá thời gian ngồi build Sagemath 10.3 từ source (do thằng package manager của ubuntu chỉ có sage 9.5). Hướng dẫn cách build tại [đây](https://sagemanifolds.obspm.fr/install_ubuntu.html)
 
### Unintended
- Đây là một bài về [Mceliece cryptosystem](https://en.wikipedia.org/wiki/McEliece_cryptosystem)(một Code-based cryptosystem) dựa trên [Reed-Solomon code](https://en.wikipedia.org/wiki/Reed%E2%80%93Solomon_error_correction). Sau một hồi osint thì mình tìm được paper khá liên quan
https://arxiv.org/pdf/1907.12754 (mục 3.1)
- Bài này, flag sẽ được cho qua hàm `encode_message` để tạo thành một array các số nhỏ hơn p. Sau đó nó đi qua hàm `encrypt`:
```python=
def encrypt(message: bytes, pubkey):
    k, n = pubkey.dimensions()
    F = pubkey[0, 0].parent()
    num_errors = (n - k) // 4 # 31
    encryptions = []
    for m in encode_message(message, F, k):
        print(m)
        error = [F.random_element() for _ in range(num_errors)] + \
            [0] * (n - num_errors)
        shuffle(error)
        error = vector(F, error)
        encryptions.append(m * pubkey + error)
    return encryptions
```
- Mấu chốt là ở phép nhân ma trận `m * pubkey + error`, trong paper họ biến đổi như sau:
![image](https://hackmd.io/_uploads/HJPoAD28A.png)
Với $\hat{G}$ là pubkey, $G_i$ là các cột của $\hat{G}$.
- Nhìn vào cách vector `error` được tạo ra, dễ thấy gồm 256 số với 31 số khác 0 (tương ứng với các lỗi). Do đó, nếu bằng một cách nào đó ta tìm được các dãy k các $index = \{i_1, i_2, ..., i_k\} \subset \{0,1,2,...,n-1\}$ sao cho error tại các $i_j$ luôn bằng 0. Vậy nên ta sẽ có:
![image](https://hackmd.io/_uploads/HyDH7O2UA.png)
- Nếu ma trận $\hat{G}$ là ma trận invertible thì dễ dàng tính $m = c * \hat{G}^{-1}$.
- Vấn đề duy nhất ta mắc phải là ta phải tìm được dãy index như thế. Ở đây, mình chỉ random k số từ dãy số từ 0 đến n-1, xác suất để tìm được nó là $p = \frac{\binom{n-31}{k}}{\binom{n}{k}}$. Do vậy mình cần lặp ít nhất `int(1/p)` lần để tìm chuỗi đó. Tuy vậy, khi thay số vào thì ta được số lần lặp rất lớn, nhân với chi phí khi tính toán ma trận nữa thì có vẻ là bất khả thi. 
- Để ý rằng, vector m có độ dài k, tuy nhiên nó có một khúc padding ở phía sau nếu flag không đủ dài. Mình đã test thử với một flag với độ dài thông thường thì có kết quả sau:
```python=
FLAG = b"CTF{aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa}"

def encode_message(message: bytes, k):
    p = 521
    message_int = int.from_bytes(message, 'big')
    message_vector = []
    while message_int:
        message_vector.append(message_int % p)
        message_int //= p
    print(len(message_vector))
    padding = k - len(message_vector) % k
    message_vector += [padding] * padding
    return [message_vector[i:i + k]
            for i in range(0, len(message_vector), k)]
print(encode_message(FLAG, 169))

```
![image](https://hackmd.io/_uploads/HyF_d_2LR.png)
Nếu đúng với flag trên, ta thực sự chỉ cần tìm 61 vị trí thay vì cả thay k vị trí, từ đó giàm được độ phức tạp xuống rất nhiều. Tuy nhiên thay vào đó ta phải brute force độ dài của chuỗi encode trước khi pad để tính giá trị padding. 
- Full script:
```python=
from sage.all import *
from Crypto.Util.number import *
import math
from tqdm import trange
p, n, k, r = 521, 256, 169, 39
pubkey = load("pubkey.sobj")
encrypted_flag = load("flag_enc.sobj")
l = 30
F = GF(p)
cnt = 0
def decode_flag(x):
	x = [int(i) for i in x]
	ret = 0
	for i in x[::-1]:
		ret *= p
		ret += i
	return long_to_bytes(ret)

while True:
	print(l)
	padding = k-l
	for i in trange(int(math.comb(295, l)/math.comb(295-31, l))):
		poses = sample(list(range(n)), l)
		cols = [pubkey.column(i) for i in poses]

		c = [encrypted_flag[0][i] for i in poses]
		c = [(c[i] - padding * sum(cols[i][l:])) % p for i in range(l)]
		c = vector(F, c)
		cols = matrix(F, [x[:l] for x in cols])
		try:
			x = cols.inverse() * c
		except:
			continue
		flag = decode_flag(list(x))
		if b'CTF{' in flag:
			print(flag)
			quit()
	l += 1

```
Và cái giá phải trả khi làm theo hướng unintended này là phải chờ script chạy hơn 1h ... 🥱
![image](https://hackmd.io/_uploads/SkSm5_n8R.png)

### Intended
https://github.com/google/google-ctf/blob/main/2024/quals/crypto-mceliece/challenge/solve.sage
Ref: https://arxiv.org/pdf/1307.6458