---
title: Potluck CTF 2024
published: 2024-07-02
description: 'Potluck CTF 2024'
image: '../logo/potluck.png'
tags: [Invalid curve attack, coppersmith multivariate, ]
category: 'CTF Writeups'
draft: false 
---
# 37C7 Potluck CTF 2023
> Đây chính là giải CTF cuối cùng của mình trong năm 2023, kết thúc một năm đáng nhớ của bản thân trong bộ môn này. Mình chơi cùng team G.0.4.7 và team mình kết thúc ở vị trí 43, bản thân mình làm được 2 câu. Sau đây là write-up của mình cho 2 câu đó và một câu làm được sau khi giải kết thúc :(.
![image](https://hackmd.io/_uploads/rJw1zPpvp.png)

## lima beans with lemon and lime
![image](https://hackmd.io/_uploads/ry9QGwpv6.png)
- final.py (đã được mình chỉnh sửa một vài tên biến để dễ đọc hơn)
```python=
#!/usr/bin/env python3

from Crypto.Util.number import getPrime, bytes_to_long
from secrets import randbelow, randbits
# from FLAG import flag
flag = b'potluck{fake_flag_343223212}'
count = 8
size = 2048
lemonSize = size // 2 * count
prime = getPrime(size)
queries = 17

def pkcs16(msg):
	filledmsg = [0 for _ in range(count)]
	msg += b'A' * ((count * size // 8) - len(msg))
	cookedmsg = bytes_to_long(msg)
	for idx in range(count):
		cookedmsg, filledmsg[idx] = divmod(cookedmsg, prime)
	print(cookedmsg)
	return filledmsg

def encrypt(msg, key, iv):
	msgWithLemonAndLime = 0
	for idx in range(count):
		lemonSlice = key[idx]
		char = msg[idx]
		if (iv >> idx) & 1:
			char **= 2		
			char %= prime
		msgWithLemonAndLime += char * lemonSlice
		msgWithLemonAndLime %= prime
	return msgWithLemonAndLime

flag = pkcs16(flag)
print(f'Hello and welcome to the lima beans with lemon and lime cryptosystem. It it so secure that it even has a {lemonSize} bit encryption key, that is {lemonSize // 256} times bigger than an AES-256, and therefore is {lemonSize // 256} times more secure')
print(f'p: {prime}')
for turn in range(queries):
	print('1: Encrypt a message\n2: Encrypt flag\n3: Decrypt message')
	choice = input('> ')
	if choice not in ('1', '2', '3'):
		print('What?')
	if choice == '1':
		msg = input('msg: ').encode()
		if len(msg) * 8 > size * count:
			print('Hmmm a bit long innit?')
			continue
		msg = pkcs16(msg)
		key = [randbelow(2**(size - 48)) for _ in range(count)]
		iv = randbits(count)
		ct = encrypt(msg, key, iv)
		print(f'ct: {ct}')
		print(f'iv: {iv}')
		print(f'key: {",".join(map(str, key))}')
	elif choice == '2':
		key = [randbelow(2**(size//2)) for _ in range(count)]
		iv = randbits(count)
		ct = encrypt(flag, key, iv)
		print(f'ct: {ct}')
		print(f'iv: {iv}')
		print(f'key: {",".join(map(str, key))}')
	else:
		print('patented, sorry')
```
- Phân tích một tí về đề bài, server cho ta 2 lựa chọn, một là encrypt message mà ta nhập, 2 là encrypt flag. Message (hoặc flag) trước khi encrypt sẽ cho đi qua hàm `pkcs16` (mình sẽ phân tích sau, đại khái nó sẽ cho ra output là mảng gồm 8 số mod p). Sau đó họ random key và iv: key là một dãy gồm 8 số bất kì, iv là 1 số < `2**8`. Tiếp theo sẽ mã hóa theo hàm encrypt. Trong hàm encrypt, msg (một dãy gồm 8 số) sẽ được mã hóa theo quy tắc: nếu bit thứ i (tính từ LSB đến MSB) của iv là 1 thì cộng dồn vào kết quả `msg[i]**2 * key[i]`, là 0 thì cộng dồn kết quả với `msg[i]*key[i]`, cuối cùng trả về kết quả.
- Nhận thấy trong handmade cryptosystem này, tất cả đều được public, vì vậy ta phải nghĩ ra hàm decrypt để tìm flag. Ý tưởng mình làm bài này đơn giản chỉ là giải hệ phương trình tuyến tính 16 ẩn, (16 ẩn trong khi đó mình chỉ cần 8 giá trị vì ở đây có sự xuất hiện của `msg[i]**2` nên mình tính nó là 1 ẩn luôn). Mà để giải hệ tuyến tính 16 ẩn thì phải có 16 phương trình, do đó ta gởi 16 request lên server để nó encrypt flag 16 lần, từ đó lập hệ phương trình rồi giải. Bây giờ chỉ cần Sagemath và một "chút" kiến thức đại số tuyến tính là có thể tìm được 8 giá trị cần tìm.
- Có được 8 giá trị đó (chính là output của flag sau khi qua hàm `pkcs16`), ta phải recover flag lại. Phân tích sơ sơ hàm này:
    - Ban đầu server pad thêm byte 'A' vào sau cho đủ 2048 bytes, sau đó chuyển về số nguyên (số này rơi vào tầm 2048*8=16384 bits hoặc ít hơn), sau đó chia cho prime, lưu lại số dư, thương số thì tiếp tục lấy để chia cho prime, tiếp tục lưu lại số dư, ... cứ như vậy cho đến khi thu được đủ 8 số dư, kết quả trả về là dãy 8 số đấy. 
    - Nhận thấy rằng ta đang còn thiếu thương số của phép chia thứ 8 để recover lại được flag. Tuy nhiên để ý kỹ, số ban đầu có độ dài khoảng 2048*8 bits, chia cho prime 8 lần (lưu ý prime dài 2048 bits), thương cuối cùng chắc chắn là số rất nhỏ (maybe bằng 0 :v). Do vậy chỉ cần brute-force giá trị thương cuối cùng, còn lại việc recover flag lại dễ như ăn cháo 😁 
- solve.py
```python=
from pwn import * 
from Crypto.Util.number import long_to_bytes
r = remote('challenge18.play.potluckctf.com',31337)
# r = process(['python3', "final.py"])
r.recvuntil(b'p: ')
p = int(r.recvuntilS(b'\n').strip())

def get_para():
    r.recvuntil(b'ct: ')
    ct = int(r.recvuntilS(b'\n').strip())
    iv = int(r.recvlineS().strip().split(':')[1])
    r.recvuntil(b'key: ')
    key = list(map(int, r.recvlineS().strip().split(',')))
    return ct, iv, key

def encrypt(msg, lemon, lime):
	msgWithLemonAndLime = 0
	for idx in range(8):
		lemonSlice = lemon[idx]
		char = msg[idx]
		if (lime >> idx) & 1:
			char **= 2		
			char %= p
		msgWithLemonAndLime += char * lemonSlice
		msgWithLemonAndLime %= p
	return msgWithLemonAndLime
# thiết lập ma trận
pos = [0] * 16
A = []
B = []
IV = []
# while all(pos):
for i in range(16):
    r.sendlineafter(b'> ', b'2')
    ct, iv, key = get_para()
    B.append(ct)
    IV.append(iv)
    row_A = []
    for idx in range(0,16,2):
        if (iv >> (idx//2)) & 1:
            pos[idx] = 1
            row_A.append(key[idx//2])
            row_A.append(0)
        else:
            pos[idx+1] = 1
            row_A.append(0)
            row_A.append(key[idx//2])
    A.append(row_A)


assert all(pos)
# print(A)
from sage.all import *  
matA = matrix(GF(p), A)
matB = matrix(GF(p),16,1, B)
X = (~matA)*matB # chia ma trận
X = [int(x[0]) for x in X]


# lấy 8 giá trị cần tìm từ kết quả 
pkcs16 = []
for i in range(0,16,2):

    if pow(X[i],2,p) == X[i+1]:
        pkcs16.append(X[i])
    elif pow(X[i+1],2,p) == X[i]:
        pkcs16.append(X[i+1])
    else:
        print('fail')
        exit()
# recover flag
t = 0
while True:
    flag = t
    print(t)
    for i in pkcs16[::-1]:
        flag = flag * p + i
    if b'potluck' not in long_to_bytes(flag):
        t += 1
        continue
    else:
        print(long_to_bytes(flag))
        break
```
- Vì server đã dead nên mình chỉ test trên local.
![image](https://hackmd.io/_uploads/H1riK_6wT.png)
## abc
![image](https://hackmd.io/_uploads/Bk5CF_pvT.png)
- chall.rs
```rust=
use rug::integer::Order;
use rug::rand::RandGen;
use rug::{rand::RandState, Complete, Integer};
use scanf::scanf;
use sha2::{Digest, Sha512};
use static_init::dynamic;
use std::fs::File;
use std::io::Read;
use std::str::FromStr;

#[dynamic]
static P192: Curve = Curve {
    p: Integer::from_str_radix("fffffffffffffffffffffffffffffffeffffffffffffffff", 16).unwrap(),
    a: Integer::from_str_radix("fffffffffffffffffffffffffffffffefffffffffffffffc", 16).unwrap(),
    b: Integer::from_str_radix("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16).unwrap(),
    G: Point {
        x: Integer::from_str_radix("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16).unwrap(),
        y: Integer::from_str_radix("07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16).unwrap(),
    },
    n: Integer::from_str_radix("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16).unwrap(),
};

#[derive(PartialEq, Eq, Clone)]
pub struct Curve {
    pub p: Integer,
    pub a: Integer,
    pub b: Integer,
    pub n: Integer,
    pub G: Point,
}

#[derive(PartialEq, Eq, Clone)]
pub struct Point {
    pub x: Integer,
    pub y: Integer,
}

impl Point {
    pub fn new(x: &Integer, y: &Integer) -> Point {
        Point {
            x: x.clone(),
            y: y.clone(),
        }
    }

    pub fn add(&self, other: &Point) -> Point {
        if self.is_inf() {
            return other.clone();
        }
        if other.is_inf() {
            return self.clone();
        }
        if self == other {
            return self.double();
        }
        let dx = (&other.x - &self.x).complete();
        let dy = (&other.y - &self.y).complete();
        let s = (dy * dx.invert(&P192.p).unwrap()).modulo(&P192.p);
        let x = ((&s * &s).complete() - &self.x - &other.x).modulo(&P192.p);
        let y = (s * (&self.x - &x).complete() - &self.y).modulo(&P192.p);
        Point { x: x, y: y }
    }

    pub fn double(&self) -> Point {
        if self.is_inf() {
            return self.clone();
        }
        let s = (((&self.x * &self.x).complete() * Integer::from(3) + &P192.a)
            * (&self.y * Integer::from(2)).invert(&P192.p).unwrap())
        .modulo(&P192.p);
        let x = ((&s * &s).complete() - &self.x - &self.x).modulo(&P192.p);
        let y = (s * (&self.x - &x).complete() - &self.y).modulo(&P192.p);
        Point { x: x, y: y }
    }

    pub fn negate(&self) -> Point {
        Point {
            x: self.x.clone(),
            y: -self.y.clone(),
        }
    }

    pub fn mul(&self, n: &Integer) -> Point {
        let mut r = Point::new(&Integer::from(0), &Integer::from(0));
        let mut m = self.clone();
        let mut n = n.clone();
        while n > 0 {
            if n.is_odd() {
                r = r.add(&m);
            }
            m = m.double();
            n >>= 1;
        }
        r
    }

    pub fn is_inf(&self) -> bool {
        self.x == 0 && self.y == 0
    }
}

struct FileRandom {
    file: File,
}

impl FileRandom {
    fn new() -> FileRandom {
        FileRandom {
            file: File::open("/dev/urandom").unwrap(),
        }
    }
}

impl RandGen for FileRandom {
    fn gen(&mut self) -> u32 {
        let mut buf = [0u8; 4];
        self.file.read_exact(&mut buf).unwrap();
        as_u32_le(&buf)
    }
}

fn as_u32_le(array: &[u8; 4]) -> u32 {
    ((array[0] as u32) << 0)
        + ((array[1] as u32) << 8)
        + ((array[2] as u32) << 16)
        + ((array[3] as u32) << 24)
}

fn hash(data: &[u8]) -> [u8; 64] {
    let mut hasher = Sha512::new();
    hasher.update(data);
    hasher.finalize().into()
}

fn encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut result = Vec::new();
    for (i, b) in data.iter().enumerate() {
        result.push(b ^ key[i % key.len()]);
    }
    result
}

fn bytes_to_hex(bytes: &[u8]) -> String {
    let mut result = String::new();
    for b in bytes {
        result.push_str(&format!("{:02x}", b));
    }
    result
}

fn int_to_bytes(i: &Integer) -> [u8; 24] {
    let mut buf = [0u8; 24];
    i.write_digits(&mut buf, Order::Lsf);
    buf
}

fn main() {
    let flag = std::env::var("FLAG")
        .unwrap_or("potluck{fake_FLAG}".into())
        .into_bytes();
    let message = "Hello, Bob. What are you bringing to the potluck???".as_bytes();

    let mut urandom = FileRandom::new();
    let mut rng = RandState::new_custom(&mut urandom);

    let d_a: Integer = P192.n.clone().random_below(&mut rng);
    let Q_a = P192.G.mul(&d_a);
    println!("Alice public key: {}, {}", Q_a.x, Q_a.y);

    print!("Input Bob public key: ");
    let mut x = String::new();
    let mut y = String::new();
    if scanf!("{}, {}", x, y).is_err() || x.len().max(y.len()) > 77 {
        println!("Invalid input");
        return;
    }
    let Q_b = Point::new(
        &Integer::from_str(&x).unwrap().modulo(&P192.p),
        &Integer::from_str(&y).unwrap().modulo(&P192.p),
    );
    let Q_ab = Q_b.mul(&d_a);
    let key_ab = int_to_bytes(&Q_ab.x);
    println!("Alice to Bob: {}", bytes_to_hex(&encrypt(message, &key_ab)));

    let d_c = P192.n.clone().random_below(&mut rng);
    let Q_c = P192.G.mul(&d_c);
    println!("Charlie public key: {}, {}", Q_c.x, Q_c.y);

    let Q_ac = Q_c.mul(&d_a);
    let key_ac = hash(&int_to_bytes(&Q_ac.x));
    println!(
        "Alice to Charlie: {}",
        bytes_to_hex(&encrypt(&flag, &key_ac))
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_point() {
        let g = P192.G.clone();
        let d = Integer::from_str("187243752983459899230757820204359986210").unwrap();
        let x = Integer::from_str("2734289461486060021208464358266994623373410779064022859147")
            .unwrap();
        let y =
            Integer::from_str("771004581668539298815067901581675228092397393541746889966").unwrap();
        let p = g.mul(&d);
        assert_eq!(p.x, x);
        assert_eq!(p.y, y);
    }
}
```
- Wtf, it's Rust. Let's use Rust to Python converter 😅
- chall.py
```python=
import random
import hashlib
import os
class Curve:
    def __init__(self, p, a, b, n, G):
        self.p = p
        self.a = a
        self.b = b
        self.n = n
        self.G = G

class Point:
    def __init__(self, x, y):
        self.x = x
        self.y = y

    def add(self, other):
        if self.is_inf():
            return other
        if other.is_inf():
            return self
        if self == other:
            return self.double()
        dx = (other.x - self.x) % P192.p
        dy = (other.y - self.y) % P192.p
        s = (dy * pow(dx,-1,P192.p)) % P192.p
        x = ((s * s) - self.x - other.x) % P192.p
        y = (s * (self.x - x) - self.y) % P192.p
        return Point(x, y)

    def double(self):
        if self.is_inf():
            return self
        s = (((self.x * self.x) * 3 + P192.a) * pow(self.y * 2,-1,P192.p)) % P192.p
        x = ((s * s) - self.x - self.x) % P192.p
        y = (s * (self.x - x) - self.y) % P192.p
        return Point(x, y)

    def negate(self):
        return Point(self.x, -self.y)

    def mul(self, n):
        r = Point(0, 0)
        m = self
        while n > 0:
            if n % 2 == 1:
                r = r.add(m)
            m = m.double()
            n >>= 1
        return r

    def is_inf(self):
        return self.x == 0 and self.y == 0

def hash(data):
    hasher = hashlib.sha512()
    hasher.update(data)
    return hasher.digest()

def encrypt(data, key):
    result = []
    for i, b in enumerate(data):
        result.append(b ^ key[i % len(key)])
    return result

def bytes_to_hex(bytes):
    result = ""
    for b in bytes:
        result += format(b, "02x")
    return result

def int_to_bytes(i):
    return i.to_bytes(24, "little")

P192 = Curve(
    int("fffffffffffffffffffffffffffffffeffffffffffffffff", 16),
    int("fffffffffffffffffffffffffffffffefffffffffffffffc", 16),
    int("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16),
    int("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16),
    Point(
        int("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16),
        int("07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16)
    )
)

class FileRandom:
    def __init__(self):
        self.file = open("/dev/urandom", "rb")

    def gen(self):
        buf = self.file.read(4)
        return int.from_bytes(buf, "little")

def main():
    flag = os.getenv("FLAG", b"potluck{fake_FLAG}")
    message = b"Hello, Bob. What are you bringing to the potluck???"
    urandom = FileRandom()
    
    rng = random.Random(urandom)
    d_a = rng.randint(0, P192.n - 1)
    Q_a = P192.G.mul(d_a)
    print(f"Alice public key: {Q_a.x}, {Q_a.y}")
    # đoạn input này hơi sai so với code rust gốc nhưng để hiểu idea thì mình để tạm như vầy
    x = input("Input Bob public key: ")
    y = input()
    
    if len(x) > 77 or len(y) > 77:
        print("Invalid input")
        return
    Q_b = Point(int(x) % P192.p, int(y) % P192.p)
    Q_ab = Q_b.mul(d_a)
    key_ab = int_to_bytes(Q_ab.x)
    print(f"Alice to Bob: {bytes_to_hex(encrypt(message, key_ab))}")
    d_c = rng.randint(0, P192.n - 1)
    Q_c = P192.G.mul(d_c)
    print(f"Charlie public key: {Q_c.x}, {Q_c.y}")
    Q_ac = Q_c.mul(d_a)
    key_ac = hash(int_to_bytes(Q_ac.x))
    print(f"Alice to Charlie: {bytes_to_hex(encrypt(flag, key_ac))}")

if __name__ == "__main__":
    main()

```

- Đây là một bài về invalid curve attack (có thể tham khảo paper [này](https://eprint.iacr.org/2017/554.pdf?ref=notamonadtutorial.com) để hiểu rõ hơn), nói sơ qua thì nó là loại attack dựa trên việc server không check xem điểm do người dùng nhập có nằm trên curve hay không. Lợi dụng điều đó, attacker có thể gởi các điểm có order yếu (thường là nhỏ), gởi cho server tính toán, vì order của base point yếu nên có thể bị tấn công bởi các thuật toán giải ECDLP như BSGS, Polard-rho, Pohlig - Hellman, ... Sau đó dùng CRT để tính toán private key. 
- Đó mới chỉ là lý thuyết, bài này đặc biệt ở chỗ chỉ cho ta query 1 lần, do đó việc gởi điểm có order nhỏ rồi dùng CRT là không hợp lí, mình sẽ phải gởi điểm có order lớn (xấp xỉ order ban đầu) nhưng muốn vậy thì order phải smooth (để sau đó có thể dùng Pohlig-Hellman để giải ECDLP), sau đó dùng Pohlig - Hellman giải quyết (thật ra là dùng hàm có sẵn thôi :))). 
- Làm sao để sinh ra điểm có smooth order (order là tích của các số nguyên tố nhỏ). Để ý kĩ [công thức cộng 2 điểm trong ECC ](https://en.wikipedia.org/wiki/Elliptic_curve_point_multiplication), ta thấy nó không hề động gì tới hệ số b, do đó nếu ta lấy một số b khác, tạo curve với số b đó, gởi cho server điểm trên curve mới thì server sẽ không phát hiện và thực hiện phép tính như thường, kết quả thu được vẫn nằm trên curve mới. Ý tưởng của mình sẽ là random b, xây dựng curve mới với b đó và check xem curve đó có smooth order không. Việc tìm kiếm nhanh hay lâu thì phải phụ thuộc vào ~~nhân phẩm~~ máy khỏe hay không 😁
```python=
from sage.all import * 
import random

p = int("fffffffffffffffffffffffffffffffeffffffffffffffff", 16)
a = int("fffffffffffffffffffffffffffffffefffffffffffffffc", 16)
b = int("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16)
n = int("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16)
Gx = int("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16)
Gy = int("07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16)

while True:
    b = random.randint(0,p-1)
    E = EllipticCurve(GF(p), [a,b])
    od = E.order()
    fac = list(factor(od))
    if all(prime < 2**45 for prime,e in fac):
        print(f'{b = }')
        break  
# b = 5286792990678095946872411039764355443644685268799870943415
```

solve.py:
```python=
from sage.all import * 
from pwn import * 
import random
import hashlib
r = remote('challenge03.play.potluckctf.com',31337)
# r = process(['python3', 'main.py'])

def xor(data, key):
    result = []
    for i, b in enumerate(data):
        result.append(b ^ key[i % len(key)])
    return bytes(result)

p = int("fffffffffffffffffffffffffffffffeffffffffffffffff", 16)
a = int("fffffffffffffffffffffffffffffffefffffffffffffffc", 16)
b = int("64210519e59c80e70fa7e9ab72243049feb8deecc146b9b1", 16)
n = int("ffffffffffffffffffffffff99def836146bc9b1b4d22831", 16)
Gx = int("188da80eb03090f67cbf20eb43a18800f4ff0afd82ff1012", 16)
Gy = int("07192b95ffc8da78631011ed6b24cdd573f977a11e794811", 16)
E = EllipticCurve(GF(p), [a,b])
r.recvuntil(b'Alice public key: ')
Q_a = E(*(list(map(int, r.recvuntilS(b'\n').strip().split(',')))))
b_ = 5286792990678095946872411039764355443644685268799870943415
E_ = EllipticCurve(GF(p), [a,b_])
G_ = E_.gen(0)
n_ = G_.order()

x,y = G_.xy()

r.sendlineafter(b'Input Bob public key: ', (str(x) + ', '+ str(y)).encode())
# r.sendline(str(y).encode())
message = b"Hello, Bob. What are you bringing to the potluck???"
enc_mess = bytes.fromhex(r.recvlineS().strip().split(':')[1])
key_ab = xor(message, enc_mess)[:24]
Qab_x = int.from_bytes(key_ab, 'little')
Qab = E_.lift_x(GF(p)(Qab_x))
print(Qab)
dlog = discrete_log(Qab, G_, operation='+')
print(dlog)

r.recvuntil(b'Charlie public key: ')
pubkey = E(*(list(map(int, r.recvuntilS(b'\n').strip().split(',')))))
enc_flag = bytes.fromhex(r.recvlineS().strip().split(':')[1])
k = 0
while True:
    can = k*n_ + dlog
    if can > n:
        exit(1)
    Q_ac = pubkey * can
    key = hashlib.sha512(int(Q_ac.xy()[0]).to_bytes(24,'little')).digest()
    flag = xor(enc_flag, key)
    if b'potluck' in flag:
        print(flag)
        break
    else:
        k += 1
```
![image](https://hackmd.io/_uploads/BkY955pwa.png)
## Upside-down Cake (sau giải)
![image](https://hackmd.io/_uploads/r1-Djqaw6.png)
- source.py
```python=
#!/usr/bin/env python3
#
# Upside-down Cake by Neobeo
# written for PotluckCTF 2023

# -----------
# Ingredients

# You'll need 44 eggs. It's considered good luck to write letters on the eggs something or something.
FLAG = b'potluck{???????????????????????????????????}'
assert len(FLAG) == 44

# -----------
# Preparation

# Set the oven to 521 degrees Fahrenheit. You might need to fiddle with the knobs a little bit.
p = ~-(-~(()==()))** 521

# Make sure you know how to crack a bunch of eggs, and also how to invert an entire cake layer.
crack = lambda eggs: int.from_bytes(eggs, 'big')
invert = lambda cake_layer: pow(cake_layer, -1, p)

# ---------------------------------------------------------------------------
# Now for the recipe itself -- it's going to be a two-layer upside-down cake!

pan = []                         # Step 1) Prepare an empty pan

layer1 = crack(FLAG[:22])        # Step 2) Crack the first half of the eggs into Layer 1
layer1 = invert(layer1)          # Step 3) This is important, you need to flip Layer 1 upside down
pan.append(layer1)               # Step 4) Now you can add Layer 1 into the pan!

layer2 = crack(FLAG[22:])        # Step 5) Crack the second half of the eggs into Layer 2
layer2 = invert(layer2)          # Step 6) This is important, you need to flip Layer 2 upside down
pan.append(layer2)               # Step 7) Now you can add Layer 2 into the pan!

upside_down_cake = sum(pan)      # Step 8) Put the pan in the oven to combine the contents into the upside-down cake
print(f'{upside_down_cake = }')  # Step 9) Your upside-down cake is ready. Enjoy!

# upside_down_cake = 5437994412763609312287807471880072729673281757441094697938294966650919649177305854023158593494881613184278290778097252426658538133266876768217809554790925406

# ----------------------------------------------------------------
# Here, I brought the cake to the potluck. Why don't you try some?

have_a_slice_of_cake = b'''
                      .: :v
                     c:  .X
                      i.::
                        :
                       ..i..
                      #MMMMM
                      QM  AM
                      9M  zM
                      6M  AM
                      2M  2MX$MM@1.
                      OM  tMMMMMMMMMM;
                 .X#MMMM  ;MMMMMMMMMMMMv
             cEMMMMMMMMMU7@MMMMMMMMMMMMM@
       .n@MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM
      MMMMMMMM@@#$BWWB#@@#$WWWQQQWWWWB#@MM.
      MM                                ;M.
      $M                                EM
      WMO$@@@@@@@@@@@@@@@@@@@@@@@@@@@@#OMM
      #M                                cM
      QM                                tM
      MM                                cMO
   .MMMM                                oMMMt
  1MO 6MMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMMM iMM
 .M1  BM                                vM  ,Mt
 1M   @M .............................. WM   M6
  MM  .A8OQWWWWWWWWWWWWWWWWWWWWWWWWWWWOAz2  #M
   MM                                      MM.
    @MMY                                vMME
      UMMMbi                        i8MMMt
         C@MMMMMbt;;i.......i;XQMMMMMMt
              ;ZMMMMMMMMMMMMMMM@'''

```
- Đây là bài có code đơn giản nhất nhưng lại gây mình khó khăn nhất. Đề bài chỉ đơn giản là chia flag làm 2 nửa, tính nghịch đảo của mỗi nửa đó theo modulo p và cộng lại và chỉ cung cấp ta kết quả phép cộng đó.
- Bài này mình sẽ phải dùng "bivariate Coppersmith" để tìm 2 nửa flag đó. Giả sử 2 nửa flag là x,y, tổng được cho là z:
Ta có: $z = x^{-1}+y^{-1}$, nhân 2 vế với ab, ta được $x+y=xyz$. Tuy nhiên nếu đưa thẳng phương trình này vào Coppersmith thì khá chắc nó sẽ trả về nghiệm (0,0). Do phần đầu flag bắt đầu bằng `potluck{` nên mình biến đổi thành `(x+x0) + y = (x+x0)*y*z` với:
```x0 = bytes_to_long(b'potluck{' + (22-8)*b'\0')```
- Ta có thể tham khảo bivariate Coppersmith tại paper [này](https://www.iacr.org/archive/eurocrypt2004/30270487/bivariate.pdf), ở đây mình sẽ tham khảo code của [defund](https://github.com/defund/coppersmith)
- solve.sage
```python=
import itertools
from sage.all import * 
def small_roots(f, bounds, m=1, d=None):
	if not d:
		d = f.degree()

	if isinstance(f, Polynomial):
		x, = polygens(f.base_ring(), f.variable_name(), 1)
		f = f(x)

	R = f.base_ring()
	N = R.cardinality()
	
	f /= f.coefficients().pop(0)
	f = f.change_ring(ZZ)

	G = Sequence([], f.parent())
	for i in range(m+1):
		base = N^(m-i) * f^i
		for shifts in itertools.product(range(d), repeat=f.nvariables()):
			g = base * prod(map(power, f.variables(), shifts))
			G.append(g)

	B, monomials = G.coefficient_matrix()
	monomials = vector(monomials)

	factors = [monomial(*bounds) for monomial in monomials]
	for i, factor in enumerate(factors):
		B.rescale_col(i, factor)

	B = B.dense_matrix().LLL()

	B = B.change_ring(QQ)
	for i, factor in enumerate(factors):
		B.rescale_col(i, 1/factor)

	H = Sequence([], f.parent().change_ring(QQ))
	for h in filter(None, B*monomials):
		H.append(h)
		I = H.ideal()
		if I.dimension() == -1:
			H.pop()
		elif I.dimension() == 0:
			roots = []
			for root in I.variety(ring=ZZ):
				root = tuple(R(root[var]) for var in f.variables())
				roots.append(root)
			return roots
	return []
from Crypto.Util.number import * 

p = ~-(-~(()==()))** 521
cake = 5437994412763609312287807471880072729673281757441094697938294966650919649177305854023158593494881613184278290778097252426658538133266876768217809554790925406
P.<x,y> = PolynomialRing(Zmod(p))
x0 = bytes_to_long(b'potluck{' + (22-8)*b'\0')
f = (x + x0) + y - (x+x0)*y*cake 
upper_boundX = bytes_to_long(14*b'\xff')
upper_boundY = bytes_to_long(22*b'\xff')

root = small_roots(f, (upper_boundX, upper_boundY))
print(root)
for r in root:
	flag = long_to_bytes((int(r[0] + x0))) + long_to_bytes(int(r[1]))
	print(flag)
```
![image](https://hackmd.io/_uploads/Hyd0xjaPT.png)
