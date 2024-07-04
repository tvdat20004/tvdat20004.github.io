---
title: Differential Fault Analysis on AES
published: 2024-07-04
description: 'Differential Fault Analysis on AES'
image: ''
tags: [AES]
category: 'Cryptography'
draft: false 
---
# Differential Fault Analysis on AES
> Reference: 
> - [1] https://blog.quarkslab.com/differential-fault-analysis-on-white-box-aes-implementations.html
> - [2] https://pure.tue.nl/ws/portalfiles/portal/88828381/1035230_B._Ezepue_Thesis_PublicVersion.pdf(2)
## Giải thích
- Differential Fault Analysis (DFA) là một phương pháp thường được dùng để tấn công vào "White-box implementations" (theo mình hiểu là implementation của cipher sẽ được public) mà sẽ có những lỗi (fault) trong cách triển khai. 
- Trong bài viết này mình chỉ thực hiện làm việc trên AES (trong ref 2 có nhắc đến cả việc tấn công trên DES). Mình sẽ giải thích sơ theo như những gì mình hiểu và trình bày cách áp dụng nó vào 1 bài CTF cụ thể. 
### Ngữ cảnh
Như đã nói ở trên thì yêu cầu của nó chính là phải có "fault" trong implementation. Cụ thể, trong AES-128 sẽ bao gồm 10 rounds, mỗi round gồm các phép biến đổi (SubByte, ShiftRow, MixColumn, AddRoundKey), riêng round 10 sẽ không có MixColumn. Giả sử có 1 byte của state bị thay đổi giữa 2 phép MixColumn cuối cùng, khi đó state bị lỗi sẽ chỉ qua 1 phép MixColumn, khi đó 1 byte lỗi sẽ kéo theo 4 byte lỗi khác ở kết quả cuối cùng (final state). Cụ thể tại sao thì ta cùng đi qua các phép biến đổi để biết chi tiết.
### Biến đổi
- Ta giả sử state bị lỗi ngay giữa ShiftRow9 và MixColumn9 như sau:

    State: 

    $\begin{matrix}
    A &  E&  I&  M\\
    B &  F&  J&  N\\
    C &  G&  K&  O\\
    D &  H&  L&  P
    \end{matrix}$

    Faulty_state: 

    $\begin{matrix}
    X &  E&  I&  M\\
    B &  F&  J&  N\\
    C &  G&  K&  O\\
    D &  H&  L&  P
    \end{matrix}$

Qua các phép biến đổi tiếp theo thì faulty_state bị biến đổi như sau:
![image](https://hackmd.io/_uploads/rkwGGQlZC.png)
![image](https://hackmd.io/_uploads/Hk4QzQeb0.png)
- Có thể thấy rằng từ 1 byte bị lỗi, qua biến đổi thì final_state sẽ bị 4 byte lỗi tương ứng. Cụ thể, nếu để ý thì ta thấy nếu 1 byte lỗi ở cột 0 thì final state sẽ có 4 byte lỗi tương ứng ở index 0,7,10,13 (ta cũng dễ dàng suy ra tương tự nếu byte lỗi ở các cột còn lại, mấu chốt là ở bước MixColumn9 và ShiftRow10). 
- Từ final state không bị lỗi, ta có $out0 = S(2A\oplus 3B \oplus C \oplus D \oplus K_{9,0}) \oplus K_{10,0}$

    $\Rightarrow 2A\oplus 3B \oplus C \oplus D \oplus K_{9,0}= S^{-1}(out0 \oplus K_{10,0})$

    Từ final state bị lỗi, ta có $outfault0 = S(2X\oplus 3B \oplus C \oplus D \oplus K_{9,0}) \oplus K_{10,0}$

    $\Rightarrow 2X\oplus 3B \oplus C \oplus D \oplus K_{9,0}= S^{-1}(outfault0 \oplus K_{10,0})$

    Xor vế theo vế 2 biểu thức trên, ta được:

    $\Rightarrow 2(A \oplus X) = S^{-1}(outfault0 \oplus K_{10,0}) \oplus S^{-1}(out0 \oplus K_{10,0})$

    Đặt $E=A \oplus X$, ta sẽ phương trình cuối cùng như sau: 

    $2(E) = S^{-1}(outfault0 \oplus K_{10,0}) \oplus S^{-1}(out0 \oplus K_{10,0})$ (*)

- Biến đổi tương tự từ các byte thứ 7, 10, 13 của final state thì ta cũng sẽ có những phương trình tương tự (*), sau đó ta sẽ tìm được 4 byte tương ứng của roundKey thứ 10, còn tìm như thế nào thì mình sẽ demo trong chall CTF sau.
## Faulty Ingredient - Hack.lu 2022
![image](https://hackmd.io/_uploads/BJ_5OogWR.png)
- Source code: 

Fluxtagram_leak0.py
```python=
import json
import os
from Crypto.Cipher import AES
import fluxtagram_leak1

############################################################################
pt = []
ct = []
ft = []
enc_flag = []
NUMBER_OF_PAIRS = 25
KEY = os.urandom(16)
FLAG = b'flag{secret_duh}'
############################################################################

def generate_plaintexts():
    global pt, NUMBER_OF_PAIRS

    print("[+] Generate Plaintexts", end='')
    for _ in range(NUMBER_OF_PAIRS):
        pt.append([int(i) for i in os.urandom(16)])
    print("\t\t\t ... done")

def generate_ciphertexts():
    global pt, ct, enc_flag, KEY

    print("[+] Generate Ciphertexts", end='')
    cipher = AES.new(KEY, AES.MODE_ECB)
    for i in range(len(pt)):
        ct.append([int(j) for j in cipher.encrypt(bytes(pt[i]))])
    print("\t\t ... done")
    
    print("[+] Encrypt Secret Ingredient", end='')
    enc_flag = [int (j) for j in cipher.encrypt(FLAG)]
    print("\t\t ... done")

    print("[+] Test Secret Ingredient Decryption", end='')
    if(cipher.decrypt(bytes(enc_flag)) == FLAG):
        print("\t ... done")
    else:
        print("\t ... ERROR")
        exit(0)

def generate_faulty_ciphertexts():
    global pt, ft, KEY

    print("[+] Test AES Implementation For Errors", end='')
    test = []
    for i in range(len(pt)):
        test.append(fluxtagram_leak1.encrypt_test(pt[i], [int(i) for i in KEY]))

    error = False
    for i in range(len(ct)):
        if(ct[i] != test[i]):
            error = True

    if(error):
        print("\t ... ERROR")
        exit(0)
    print("\t ... done")

    print("[+] Generate Faulty Ciphertexts", end='')
    for i in range(len(pt)):
        ft.append(fluxtagram_leak1.encrypt_faulty(pt[i], [int(i) for i in KEY]))
    print("\t\t ... done")

def challenge_output():
    global pt, ct, ft, enc_flag

    print("[+] Generate Challenge Output", end='')
    with open("plaintext1.json", "w", encoding = 'utf-8') as f:
        f.write(json.dumps(pt))
    with open("ciphertext1.json", "w", encoding = 'utf-8') as f:
        f.write(json.dumps(ct))
    with open("faulty_ciphertext1.json", "w", encoding = 'utf-8') as f:
        f.write(json.dumps(ft))
    with open("secret_ingredient1.json", "w", encoding = 'utf-8') as f:
        f.write(json.dumps(enc_flag))
    print("\t\t ... done")

def main():
    print(KEY)
    generate_plaintexts()
    generate_ciphertexts()
    generate_faulty_ciphertexts()
    challenge_output()
    print("[!] All Done! Happy Solving :)")

if __name__ == "__main__":
    main()
```
Fluxtagram_leak1.py
```python=
from os import urandom

############################################################################
# AES ENCRYPTION but something is faulty here
############################################################################
# CONSTANTS
sbox = (
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
        )

rcon = (0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36)
############################################################################
# AES HELPER STUFF
def g(word, round):
    v_0 = word >> 24
    v_1 = word >> 16 & 0xFF
    v_2 = word >> 8 & 0xFF
    v_3 = word & 0xFF

    v_0 = sbox[v_0]
    v_1 = sbox[v_1]
    v_2 = sbox[v_2]
    v_3 = sbox[v_3]

    v_1 ^= rcon[round]

    return v_1 << 24 ^ v_2 << 16 ^ v_3 << 8 ^ v_0

def gf_mul123(inp, factor):
    if(factor == 1):
        return inp
    elif(factor == 2):
        c = inp << 1
        if((inp >> 7) & 1) == 1:
            c ^= 0x11b
        return c
    elif(factor == 3):
        return (gf_mul123(inp, 2) ^ inp)
    print("Whats wrong with you, it says mul123 not 4")
    exit(0) 
############################################################################
# AES
def key_schedule_128(key):
    roundkeys = [[0] * 16 for _ in range(11)]
    words = []

    for i in range(0, 16, 4):
        words.append(key[i] << 24 ^ key[i+1] << 16 ^ key[i+2] << 8 ^ key[i+3])

    for i in range(10):
        words.append(words[-4] ^ g(words[-1], i))
        for _ in range(3):
            words.append(words[-4] ^ words[-1])

    for i in range(11):
        for j in range(0, 16, 4):
            roundkeys[i][j] = words[j // 4 + i * 4] >> 24
            roundkeys[i][j+1] = words[j // 4 + i * 4] >> 16 & 0xFF
            roundkeys[i][j+2] = words[j // 4 + i * 4] >> 8 & 0xFF
            roundkeys[i][j+3] = words[j // 4 + i * 4] & 0xFF
    return roundkeys

def add_roundkey(state, roundkey):
    for i in range(len(state)):
        state[i] ^= roundkey[i]

def mix_columns(state):
    for i in range(0, 16, 4):
        t = state[i:i+4]
        state[i] = gf_mul123(t[0], 2) ^ gf_mul123(t[1], 3) ^ gf_mul123(t[2], 1) ^ gf_mul123(t[3], 1)
        state[i+1] = gf_mul123(t[0], 1) ^ gf_mul123(t[1], 2) ^ gf_mul123(t[2], 3) ^ gf_mul123(t[3], 1)
        state[i+2] = gf_mul123(t[0], 1) ^ gf_mul123(t[1], 1) ^ gf_mul123(t[2], 2) ^ gf_mul123(t[3], 3)
        state[i+3] = gf_mul123(t[0], 3) ^ gf_mul123(t[1], 1) ^ gf_mul123(t[2], 1) ^ gf_mul123(t[3], 2)

# This possibly can not be the source of the fault, looks complicated
def introduce_fault(state):
    for i in range(4):
        j, fault = int(urandom(1)[0]) % 4, urandom(1)[0]
        state[i * 4 + j] ^= fault


def enc_round(state, roundkey, last = False, fault = False):
    # S-Box
    for index, value in enumerate(state):
        state[index] = sbox[value]

    # Shift-row  
    state[1], state[5], state[9], state[13] = state[5], state[9], state[13], state[1]
    state[2], state[6], state[10], state[14] = state[10], state[14], state[2], state[6]
    state[3], state[7], state[11], state[15] = state[15], state[3], state[7], state[11]

    if(fault):
        introduce_fault(state)

    # Mix-Columns
    if(not last):
        mix_columns(state)

    # Key Addition
    add_roundkey(state, roundkey)

############################################################################
# MAIN FUNCTIONS
def encrypt_test(pt, key):
    state = pt.copy()
    roundkeys = key_schedule_128(key)

    add_roundkey(state, roundkeys[0])

    for i in range(1,10):
        enc_round(state, roundkeys[i])

    enc_round(state, roundkeys[10], True)

    return state
def encrypt_faulty(pt, key):
    state = pt.copy()
    roundkeys = key_schedule_128(key)
    print(roundkeys[10])
    add_roundkey(state, roundkeys[0])

    for i in range(1,9):
        enc_round(state, roundkeys[i])

    enc_round(state, roundkeys[9], fault=True)
    enc_round(state, roundkeys[10], last=True)

    return state
```
- Các file json ở [đây](https://github.com/tvdat20004/CTF_write-up/tree/main/hacklu%202023/Faulty%20Ingredient/leaked_traces)
### Phân tích source code

- Trong file "fluxtagram_leak1.py", đề bài đã cung cấp cho chúng ta cách họ implement AES. Mọi bước đều khá là bình thường, tuy nhiên nếu để ý các dòng comment của đề thì ta dễ thấy hàm `encrypt_fault` có gọi dòng `enc_round(state, roundkeys[9], fault=True)`, đại khái họ sẽ gây lỗi trong round thứ 9 (cụ thể là giữa ShiftRow9 và MixColumn9). Hàm tạo lỗi chính là `introduce_fault`.
- Hàm `introduce_fault` có tác dụng là corrupt mỗi cột một byte bất kì bằng cách xor với 1 byte khác bất kỳ (thực ra trong code họ trình bày state khác với cách trình bày state như của AES mình trình bày ở trên nên ta thấy trong code corrupt mỗi dòng một byte).
### Áp dụng DFA 
- Như mình có phân tích trong phần DFA, cứ 1 byte bị corrupt thì sẽ có 4 byte bị đổi trong final_state, vả lại vị trí của các state bị lỗi trong final_state cũng có thể xác định được. 1 byte ở cột 0 bị corrupt sẽ khiến 4 byte có vị trí 0,7,10,13 bị corrupt theo, ta sẽ có:
```python=
# position of corrupted bytes in final state
pos = [[0,7,10,13], [4,1,14,11], [8,5,2,15], [12,9,6,3]]
```
> ở đây 1 byte ở cột i sẽ kéo theo 4 byte ở các vị trí pos[i] bị corrupted
- Một vấn đề nữa, khi thiết lập phương trình `(*)`, số 2 trong phương trình sẽ phụ thuộc vào vị trí của byte bị corrupt trong cột. Điều này có nghĩa là, giả dụ state[1] bị corrupt, nó sẽ kéo theo 4 byte 0,7,10,13 trong final state bị corrupt, tuy nhiên khi biến đổi phương trình ra như (*) thì ta sẽ thu được $3E= S^{-1}(outfault0 \oplus K_{10,0}) \oplus S^{-1}(out0 \oplus K_{10,0})$ (2 -> 3), ngoài ra tham số đó còn phụ thuộc vào bị trí của byte trong final state bị corrupt nữa (vì phương trình trên sẽ ứng với 1 byte bị corrupt trong final state).
- Còn về vấn đề giải quyết phương trình, mình chỉ có thể nghĩ được cách brute-force 🤔, vì độ phức tạp không cao lắm nên mình đâm theo lao luôn 😅. Hàm giải phương trình trên như sau:
```python=
# solve this equation: para*faulty_value = inverse_sbox(out ^ k) ^ inverse_sbox(out_fault ^ k)
def solve_equation(faulty_value, out, out_fault, para):
    res = []
    for index1 in range(256):
        index2 = (out ^ out_fault) ^ index1
        if inverse_sbox[index1] ^ inverse_sbox[index2] == gf_mul123(faulty_value,para):
            res.append(index1 ^ out)
    return res
para_mat = [[2,1,1,3] * 4, [3,2,1,1]*4, [1,3,2,1]*4, [1,1,3,2]*4]
```
> para_mat là các số ta đưa vào para, vấn đề là lựa chọn chỉ số i,j cho phù hợp
- Ta sẽ có hàm giải DFA như sau:
```python=
# find common element of 2 list
def common_element(l1 : list, l2 : list):
    if len(l1) == 0 or len(l2) == 0:
        return None
    for i in l1:
        if i in l2:
            return i 
    return None
def dfa(col, fault1, fault2, cell1, cell2):
    result = []
    for i in pos[col]:
        sol1 = solve_equation(fault1, ct[0][i], faulty_ct[0][i], para_mat[cell1][i])
        sol2 = solve_equation(fault2, ct[1][i], faulty_ct[1][i], para_mat[cell2][i])
        c = common_element(sol1, sol2)   
        if c:
            result.append(c)
        else:
            return None
    return result
```
> Ở đây hàm `dfa` có các tham số col (cột của byte bị corrupt lúc đầu), fault1 và fault2 (giá trị mà hàm `introduce_fault` xor vào mỗi byte của state), cell1 và cell2 (vị trí của byte bị corrupt trong cột, dùng để xác định tham số `para` trong hàm `solve_equation`)
> Hàm này mình phải dùng tới 2 ciphertext, tại vì mỗi lần hàm `solve_equation` đều trả về 2 giá trị (trừ trường hợp vô nghiệm do tham số sai thì không tính). Do các ciphertext được encrypt chung bằng 1 key nên round_key của chúng như nhau => mình sẽ giải trên 2 ciphertext rồi tìm nghiệm chung. 
- Công việc cuối cùng chính là brute force các tham số của hàm dfa. Vì độ phức tạp khá lớn nên mình "mạn phép" áp dụng multithread vào để brute cho nhanh, cụ thể mình chia 4 thread, mỗi thread sẽ giải dfa cho mỗi giá trị col. 
```python=

lastRoundKey = [None]*16

def brute(col):
    isBreak = False
    for fault in trange(256**2):
        fault1, fault2 = fault//256, fault%256
        for j in range(16):
            j1, j2 = j//4, j%4
            sol = dfa(col, fault1, fault2, j1, j2)
            if sol:
                for i in range(4):
                    lastRoundKey[pos[col][i]] = sol[i]
                isBreak = True
                break
        if isBreak:
            break 

threads = [threading.Thread(target=brute, args=(col,)) for col in range(4)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()

print(lastRoundKey)
# lastRoundKey = [178, 54, 86, 62, 78, 61, 224, 159, 86, 231, 247, 114, 96, 170, 82, 188]
```
- Có được round_key thứ 10 rồi thì việc tìm ngược lại key khá đơn giản ~~(nếu dùng [tool](https://github.com/fanosta/aeskeyschedule) :>)~~, cuối cùng là dùng key đó để decrypt flag.
```python=
from aeskeyschedule import reverse_key_schedule
key = reverse_key_schedule(bytes(lastRoundKey), 10)
print(key)
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(bytes(enc_flag)))
```
- Full solve
```python=
from Crypto.Cipher import AES
from fluxtagram_leak1 import gf_mul123
from Crypto.Util.number import *
from tqdm import trange
import threading
pt = eval(open("./leaked_traces/plaintext.json", "r").read())
ct = eval(open("./leaked_traces/ciphertext.json", "r").read())
faulty_ct = eval(open("./leaked_traces/faulty_ciphertext.json", "r").read())
enc_flag = eval(open("./leaked_traces/secret_ingredient.json", "r").read())

inverse_sbox = (
    0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb,
    0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb,
    0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e,
    0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25,
    0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92,
    0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84,
    0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06,
    0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b,
    0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73,
    0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e,
    0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b,
    0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4,
    0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f,
    0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef,
    0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61,
    0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d
)
# solve this equation: para*faulty_value = inverse_sbox(out ^ k) ^ inverse_sbox(out_fault ^ k)
def solve_equation(faulty_value, out, out_fault, para):
    res = []
    for index1 in range(256):
        index2 = (out ^ out_fault) ^ index1
        if inverse_sbox[index1] ^ inverse_sbox[index2] == gf_mul123(faulty_value,para):
            res.append(index1 ^ out)
    return res
para_mat = [[2,1,1,3] * 4, [3,2,1,1]*4, [1,3,2,1]*4, [1,1,3,2]*4]

# position of corrupted bytes in final state
pos = [[0,7,10,13], [4,1,14,11], [8,5,2,15], [12,9,6,3]]

def common_element(l1 : list, l2 : list):
    if len(l1) == 0 or len(l2) == 0:
        return None
    for i in l1:
        if i in l2:
            return i 
    return None
def dfa(col, fault1, fault2, cell1, cell2):
    result = []
    for i in pos[col]:
        sol1 = solve_equation(fault1, ct[0][i], faulty_ct[0][i], para_mat[cell1][i])
        sol2 = solve_equation(fault2, ct[1][i], faulty_ct[1][i], para_mat[cell2][i])
        c = common_element(sol1, sol2)   
        if c:
            result.append(c)
        else:
            return None
    return result

lastRoundKey = [None]*16

def brute(col):
    isBreak = False
    for fault in trange(256**2):
        fault1, fault2 = fault//256, fault%256
        for j in range(16):
            j1, j2 = j//4, j%4
            sol = dfa(col, fault1, fault2, j1, j2)
            if sol:
                for i in range(4):
                    lastRoundKey[pos[col][i]] = sol[i]
                isBreak = True
                break
        if isBreak:
            break 

threads = [threading.Thread(target=brute, args=(col,)) for col in range(4)]
for thread in threads:
    thread.start()
for thread in threads:
    thread.join()

print(lastRoundKey)
# lastRoundKey = [178, 54, 86, 62, 78, 61, 224, 159, 86, 231, 247, 114, 96, 170, 82, 188]
from aeskeyschedule import reverse_key_schedule
key = reverse_key_schedule(bytes(lastRoundKey), 10)
print(key)
cipher = AES.new(key, AES.MODE_ECB)
print(cipher.decrypt(bytes(enc_flag)))
```
![image](https://hackmd.io/_uploads/ryzna3eWR.png)
> Chỉ mất gần 4 phút để có được flag
-> flag{Th3_s3cr3t_inGreDient_is_oni0n_powd3r_h3h3}
