#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SM2椭圆曲线密码算法基础实现
遵循GB/T 32905-2016《信息安全技术 SM2椭圆曲线公钥密码算法》
"""

import random
import hashlib
from typing import Tuple, Optional

# SM2推荐的椭圆曲线参数
p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A
n = 0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7
Gx = 0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D
Gy = 0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2

# 点坐标表示，无穷远点用None表示
Point = Optional[Tuple[int, int]]

def mod_inverse(a: int, m: int) -> int:
    """扩展欧几里得算法计算模逆"""
    g, x, y = extended_gcd(a, m)
    if g != 1:
        raise ValueError("模逆不存在")
    return x % m

def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """扩展欧几里得算法，返回(gcd, x, y)满足a*x + b*y = gcd"""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = extended_gcd(b % a, a)
        return (g, x - (b // a) * y, y)

def point_add(p1: Point, p2: Point) -> Point:
    """椭圆曲线点加法"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    
    x1, y1 = p1
    x2, y2 = p2
    
    # 处理p1 = -p2的情况
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    
    # 计算斜率
    if p1 != p2:
        dx = (x2 - x1) % p
        dy = (y2 - y1) % p
        inv_dx = mod_inverse(dx, p)
        k = (dy * inv_dx) % p
    else:
        # 点加倍
        k_numerator = (3 * x1 * x1 + a) % p
        k_denominator = (2 * y1) % p
        inv_denominator = mod_inverse(k_denominator, p)
        k = (k_numerator * inv_denominator) % p
    
    # 计算结果点
    x3 = (k * k - x1 - x2) % p
    y3 = (k * (x1 - x3) - y1) % p
    
    return (x3, y3)

def point_multiply(p: Point, k: int) -> Point:
    """椭圆曲线点乘法，使用快速幂算法"""
    result = None
    current = p
    
    while k > 0:
        if k % 2 == 1:
            result = point_add(result, current)
        current = point_add(current, current)
        k = k // 2
    
    return result

def generate_key_pair() -> Tuple[int, Point]:
    """生成SM2密钥对 (私钥d, 公钥P)"""
    # 生成私钥d，1 < d < n-1
    d = random.randint(2, n-2)
    # 计算公钥P = d*G
    P = point_multiply((Gx, Gy), d)
    return d, P

def sm3_hash(data: bytes) -> bytes:
    """计算SM3哈希值"""
    # 注意：Python 3.11+ 原生支持sm3，低版本需要使用gmssl库
    try:
        return hashlib.sm3(data).digest()
    except AttributeError:
        from gmssl import sm3
        return sm3.sm3_hash(list(data))

def calculate_z(id: bytes, public_key: Point) -> bytes:
    """计算SM2中的Z值"""
    # 计算ENTLA = len(ID) * 8
    entla = len(id) * 8
    
    # 构建数据：ENTLA || ID || a || b || Gx || Gy || Px || Py
    data = (
        entla.to_bytes(2, byteorder='big') +
        id +
        a.to_bytes(32, byteorder='big') +
        b.to_bytes(32, byteorder='big') +
        Gx.to_bytes(32, byteorder='big') +
        Gy.to_bytes(32, byteorder='big') +
        public_key[0].to_bytes(32, byteorder='big') +
        public_key[1].to_bytes(32, byteorder='big')
    )
    
    return sm3_hash(data)

def sign(d: int, message: bytes, z: bytes) -> Tuple[int, int]:
    """SM2签名算法"""
    # 计算e = Hv(Z || M)
    e_bytes = sm3_hash(z + message)
    e = int.from_bytes(e_bytes, byteorder='big')
    
    while True:
        # 生成随机数k
        k = random.randint(2, n-2)
        # 计算k*G
        kG = point_multiply((Gx, Gy), k)
        if kG is None:
            continue
        x1, _ = kG
        
        # 计算r = (e + x1) mod n
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        
        # 计算s = ((1 + d)^-1 * (k - r*d)) mod n
        inv_1d = mod_inverse(1 + d, n)
        s = (inv_1d * (k - r * d)) % n
        if s == 0:
            continue
        
        return (r, s)

def verify(public_key: Point, message: bytes, z: bytes, r: int, s: int) -> bool:
    """SM2验证算法"""
    # 检查r和s的范围
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    
    # 计算e = Hv(Z || M)
    e_bytes = sm3_hash(z + message)
    e = int.from_bytes(e_bytes, byteorder='big')
    
    # 计算t = (r + s) mod n
    t = (r + s) % n
    if t == 0:
        return False
    
    # 计算s*G + t*P
    sG = point_multiply((Gx, Gy), s)
    tP = point_multiply(public_key, t)
    if sG is None or tP is None:
        return False
    
    x1y1 = point_add(sG, tP)
    if x1y1 is None:
        return False
    x1, _ = x1y1
    
    # 计算R = (e + x1) mod n
    R = (e + x1) % n
    
    return R == r

# 测试函数
def test_sm2_base():
    """测试SM2基础功能"""
    # 生成密钥对
    d, P = generate_key_pair()
    print(f"私钥: {hex(d)}")
    print(f"公钥: ({hex(P[0])}, {hex(P[1])})")
    
    # 准备数据
    user_id = b"user@example.com"
    message = b"Hello, SM2!"
    
    # 计算Z值
    z = calculate_z(user_id, P)
    print(f"Z值: {z.hex()}")
    
    # 签名
    r, s = sign(d, message, z)
    print(f"签名结果: r={hex(r)}, s={hex(s)}")
    
    # 验证
    valid = verify(P, message, z, r, s)
    print(f"签名验证: {'成功' if valid else '失败'}")
    assert valid, "签名验证失败"
    
    # 验证篡改后的消息
    tampered_msg = b"Hello, SM2! Tampered"
    valid_tampered = verify(P, tampered_msg, z, r, s)
    print(f"篡改消息验证: {'成功' if valid_tampered else '失败'}")
    assert not valid_tampered, "篡改消息验证不应该成功"
    
    print("所有SM2基础测试通过!")

if __name__ == "__main__":
    test_sm2_base()
