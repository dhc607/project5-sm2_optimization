#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SM2椭圆曲线密码算法优化实现
基于基础实现进行了性能优化，包括点运算优化和预计算
"""

import random
import hashlib
from typing import Tuple, Optional, List
from src.sm2_base import (
    p, a, b, n, Gx, Gy, mod_inverse, extended_gcd,
    Point, sm3_hash, generate_key_pair
)

# 预计算G的幂次表，加速点乘法
def precompute_g_table() -> List[Point]:
    """预计算G的2^k倍点，用于加速点乘法"""
    table = [None] * 256  # 覆盖n的二进制长度
    current = (Gx, Gy)
    table[0] = current
    for i in range(1, 256):
        current = point_double(current)
        table[i] = current
    return table

# 预计算G的幂次表
G_TABLE = precompute_g_table()

def point_double(p: Point) -> Point:
    """专门优化的点加倍运算"""
    if p is None:
        return None
    
    x1, y1 = p
    
    # 计算斜率 k = (3x1² + a) / (2y1)
    k_numerator = (3 * x1 * x1 + a) % p
    k_denominator = (2 * y1) % p
    inv_denominator = mod_inverse(k_denominator, p)
    k = (k_numerator * inv_denominator) % p
    
    # 计算结果点
    x3 = (k * k - 2 * x1) % p
    y3 = (k * (x1 - x3) - y1) % p
    
    return (x3, y3)

def point_add(p1: Point, p2: Point) -> Point:
    """优化的点加法实现"""
    if p1 is None:
        return p2
    if p2 is None:
        return p1
    
    x1, y1 = p1
    x2, y2 = p2
    
    # 处理p1 = -p2的情况
    if x1 == x2 and (y1 + y2) % p == 0:
        return None
    
    # 快速处理同一点的情况（调用专门的double函数）
    if p1 == p2:
        return point_double(p1)
    
    # 不同点的加法
    dx = (x2 - x1) % p
    dy = (y2 - y1) % p
    inv_dx = mod_inverse(dx, p)
    k = (dy * inv_dx) % p
    
    # 计算结果点
    x3 = (k * k - x1 - x2) % p
    y3 = (k * (x1 - x3) - y1) % p
    
    return (x3, y3)

def point_multiply(p: Point, k: int) -> Point:
    """优化的点乘法实现，使用窗口法加速计算"""
    if p is None or k == 0:
        return None
    
    # 特殊情况：如果是G点，使用预计算表加速
    if p == (Gx, Gy):
        result = None
        current_bit = 0
        while k > 0:
            if k & 1:
                if result is None:
                    result = G_TABLE[current_bit]
                else:
                    result = point_add(result, G_TABLE[current_bit])
            k >>= 1
            current_bit += 1
        return result
    
    # 通用情况：使用4位窗口法
    window_size = 4
    window_mask = (1 << window_size) - 1
    
    # 预计算窗口表
    table = [None] * (1 << window_size)
    table[1] = p
    for i in range(2, 1 << window_size, 2):
        table[i] = point_double(table[i >> 1])
        table[i + 1] = point_add(table[i], p)
    
    # 计算结果
    result = None
    k_bits = k.bit_length()
    i = k_bits - 1
    
    while i >= 0:
        if (k >> i) & 1:
            # 提取连续的window_size位
            bits = 0
            for j in range(window_size):
                if i - j >= 0:
                    bits = (bits << 1) | ((k >> (i - j)) & 1)
                else:
                    bits = bits << 1
            # 添加对应的值
            if result is None:
                result = table[bits]
            else:
                result = point_add(result, table[bits])
            i -= window_size
        else:
            i -= 1
        # 每步都将结果加倍
        if i >= 0 and result is not None:
            result = point_double(result)
    
    return result

def calculate_z(id: bytes, public_key: Point) -> bytes:
    """优化的Z值计算"""
    # 计算ENTLA = len(ID) * 8
    entla = len(id) * 8
    
    # 使用bytearray减少内存复制
    data = bytearray()
    data.extend(entla.to_bytes(2, byteorder='big'))
    data.extend(id)
    data.extend(a.to_bytes(32, byteorder='big'))
    data.extend(b.to_bytes(32, byteorder='big'))
    data.extend(Gx.to_bytes(32, byteorder='big'))
    data.extend(Gy.to_bytes(32, byteorder='big'))
    data.extend(public_key[0].to_bytes(32, byteorder='big'))
    data.extend(public_key[1].to_bytes(32, byteorder='big'))
    
    return sm3_hash(bytes(data))

def sign(d: int, message: bytes, z: bytes) -> Tuple[int, int]:
    """优化的签名算法"""
    # 计算e = Hv(Z || M)
    e_bytes = sm3_hash(z + message)
    e = int.from_bytes(e_bytes, byteorder='big')
    
    # 预计算(1 + d)^-1，避免重复计算
    inv_1d = mod_inverse(1 + d, n)
    
    while True:
        # 使用更强的随机数生成器
        k = random.SystemRandom().randint(2, n-2)
        # 计算k*G，使用优化的点乘法
        kG = point_multiply((Gx, Gy), k)
        if kG is None:
            continue
        x1, _ = kG
        
        # 计算r = (e + x1) mod n
        r = (e + x1) % n
        if r == 0 or r + k == n:
            continue
        
        # 计算s
        s = (inv_1d * (k - r * d)) % n
        if s == 0:
            continue
        
        return (r, s)

def verify(public_key: Point, message: bytes, z: bytes, r: int, s: int) -> bool:
    """优化的验证算法"""
    # 快速检查r和s的范围
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    
    # 计算e
    e_bytes = sm3_hash(z + message)
    e = int.from_bytes(e_bytes, byteorder='big')
    
    # 计算t
    t = (r + s) % n
    if t == 0:
        return False
    
    # 优化点乘法计算
    sG = point_multiply((Gx, Gy), s)
    tP = point_multiply(public_key, t)
    
    if sG is None or tP is None:
        return False
    
    x1y1 = point_add(sG, tP)
    if x1y1 is None:
        return False
    x1, _ = x1y1
    
    # 计算R并验证
    R = (e + x1) % n
    return R == r

# 性能测试函数
def test_performance():
    """测试优化实现的性能提升"""
    import time
    
    # 生成密钥对
    d, P = generate_key_pair()
    user_id = b"performance@test.com"
    message = b"Test message for performance evaluation"
    z = calculate_z(user_id, P)
    
    # 测试签名性能
    start = time.time()
    for _ in range(100):
        sign(d, message, z)
    sign_time = time.time() - start
    
    # 生成一个签名用于验证测试
    r, s = sign(d, message, z)
    
    # 测试验证性能
    start = time.time()
    for _ in range(1000):
        verify(P, message, z, r, s)
    verify_time = time.time() - start
    
    print(f"SM2优化实现性能测试:")
    print(f"100次签名时间: {sign_time:.6f}秒")
    print(f"1000次验证时间: {verify_time:.6f}秒")
    
    # 验证功能正确性
    valid = verify(P, message, z, r, s)
    assert valid, "签名验证失败"
    print("功能验证通过!")

if __name__ == "__main__":
    test_performance()
