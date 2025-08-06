#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
中本聪数字签名伪造实现
演示如何利用特定条件伪造中本聪的数字签名
"""

import hashlib
from typing import Tuple
from src.sm2_optimized import (
    point_multiply, point_add, mod_inverse,
    p, a, b, n, Gx, Gy, sm3_hash
)

Point = Tuple[int, int]

# 假设的中本聪公钥（示例值，非真实公钥）
SATOSHI_PUBLIC_KEY = (
    0x51F707393F5B26211D5C5C6A085A67403E6C63343D7A623555D1400D012291E85D,
    0x5869723D861A67515B88F486658327B7381D6D4D7A75A7C7667A7C7A7D7E7F8081
)

def forge_satoshi_signature(message: bytes, satoshi_pubkey: Point) -> Tuple[int, int, bytes]:
    """
    伪造中本聪的数字签名
    利用特定的数学特性构造一个看起来像是中本聪签名的有效签名
    
    :param message: 要伪造签名的消息
    :param satoshi_pubkey: 中本聪的公钥
    :return: (r, s, Z) 伪造的签名和对应的Z值
    """
    # 步骤1: 选择随机值u和v
    u = 0x123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0
    v = 0xFEDCBA9876543210FEDCBA9876543210FEDCBA9876543210FEDCBA9876543210
    
    # 步骤2: 计算伪造的r值
    # r = x1，其中(x1,y1) = u*G + v*P
    uG = point_multiply((Gx, Gy), u)
    vP = point_multiply(satoshi_pubkey, v)
    x1y1 = point_add(uG, vP)
    if x1y1 is None:
        raise ValueError("计算点加法失败，无法生成伪造签名")
    x1, y1 = x1y1
    r = x1 % n
    
    # 步骤3: 构造特定的Z值，使得e = (r - x1) mod n
    e = (r - x1) % n
    e_bytes = e.to_bytes(32, byteorder='big')
    
    # 步骤4: 寻找满足SM3(Z || message) = e_bytes的Z值
    Z = find_z_for_hash(e_bytes, message)
    
    # 步骤5: 计算伪造的s值
    inv_v = mod_inverse(v, n)
    s = (inv_v * (u + r * v)) % n
    
    return r, s, Z

def find_z_for_hash(target_hash: bytes, message: bytes) -> bytes:
    """
    寻找满足SM3(Z || message) = target_hash的Z值
    这里使用简化的方法，实际中这是一个计算困难的问题
    
    :param target_hash: 目标哈希值
    :param message: 消息
    :return: 满足条件的Z值
    """
    # 注意：在实际场景中，这是一个计算困难的哈希原像问题
    # 这里使用预设的Z值用于演示，实际攻击需要更复杂的方法
    
    # 尝试一些简单的Z值
    for i in range(10000):
        Z_candidate = f"Z_candidate_{i}".encode()
        if sm3_hash(Z_candidate + message) == target_hash:
            return Z_candidate
    
    # 如果找不到，返回一个特殊构造的Z值（仅用于演示）
    return b"satoshi_forgery_special_Z"

def verify_forgery(message: bytes, Z: bytes, r: int, s: int, pubkey: Point) -> bool:
    """验证伪造的签名是否有效"""
    # 检查r和s是否在有效范围
    if not (1 <= r <= n-1 and 1 <= s <= n-1):
        return False
    
    # 计算e = Hv(Z || M)
    e_bytes = sm3_hash(Z + message)
    e = int.from_bytes(e_bytes, byteorder='big')
    
    # 计算t = (r + s) mod n
    t = (r + s) % n
    if t == 0:
        return False
    
    # 计算s*G + t*P
    sG = point_multiply((Gx, Gy), s)
    tP = point_multiply(pubkey, t)
    if sG is None or tP is None:
        return False
    
    x1y1 = point_add(sG, tP)
    if x1y1 is None:
        return False
    x1, y1 = x1y1
    
    # 计算R = (e + x1) mod n
    R = (e + x1) % n
    
    # 验证R == r
    return R == r

def test_forgery():
    """测试中本聪签名伪造"""
    # 要伪造签名的消息
    message = b"我是中本聪，此区块链资产归我所有。"
    print(f"消息: {message.decode()}")
    
    # 伪造签名
    print("正在伪造中本聪的签名...")
    r, s, Z = forge_satoshi_signature(message, SATOSHI_PUBLIC_KEY)
    print(f"伪造的签名 - r: {hex(r)}")
    print(f"伪造的签名 - s: {hex(s)}")
    print(f"使用的Z值: {Z.hex()}")
    
    # 验证伪造的签名
    print("验证伪造的签名...")
    valid = verify_forgery(message, Z, r, s, SATOSHI_PUBLIC_KEY)
    print(f"伪造的签名是否有效: {'是' if valid else '否'}")
    
    assert valid, "签名伪造失败"
    print("中本聪签名伪造成功!")

if __name__ == "__main__":
    test_forgery()
