#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SM2签名算法误用的POC验证
实现了文档中提到的几种常见误用场景的攻击演示
"""

import random
from typing import Tuple
from src.sm2_optimized import (
    generate_key_pair, sign, verify, calculate_z,
    point_multiply, point_add, mod_inverse, n, Gx, Gy, sm3_hash
)

Point = Tuple[int, int]

def scenario1_reused_k(d: int, M1: bytes, M2: bytes, Z1: bytes, Z2: bytes) -> Tuple[int, bool]:
    """
    场景1: 重复使用随机数k签名不同消息
    攻击目标: 从两个使用相同k的签名中恢复私钥d
    """
    # 使用相同的k进行两次签名
    k = random.randint(2, n-2)  # 被重复使用的随机数
    
    # 对消息M1签名
    e1_bytes = sm3_hash(Z1 + M1)
    e1 = int.from_bytes(e1_bytes, byteorder='big')
    kG = point_multiply((Gx, Gy), k)
    x1, _ = kG
    r1 = (e1 + x1) % n
    inv_1d = mod_inverse(1 + d, n)
    s1 = (inv_1d * (k - r1 * d)) % n
    
    # 对消息M2使用相同的k签名
    e2_bytes = sm3_hash(Z2 + M2)
    e2 = int.from_bytes(e2_bytes, byteorder='big')
    # 注意这里使用了相同的k和x1
    r2 = (e2 + x1) % n
    s2 = (inv_1d * (k - r2 * d)) % n
    
    # 攻击：从两个签名中恢复私钥d
    numerator = (s1 - s2) * (e1 - e2) % n
    denominator = (s2 * r1 - s1 * r2) % n
    if denominator == 0:
        return 0, False  # 攻击失败
    
    d_recovered = (numerator * mod_inverse(denominator, n)) % n
    
    # 验证恢复的私钥是否正确
    success = (d_recovered == d)
    return d_recovered, success

def scenario2_fixed_k(d: int, M: bytes, Z: bytes, fixed_k: int) -> Tuple[Tuple[int, int], bool]:
    """
    场景2: 使用固定的k进行签名
    攻击目标: 伪造新消息的签名
    """
    # 使用固定的k对原始消息签名
    k = fixed_k
    e_bytes = sm3_hash(Z + M)
    e = int.from_bytes(e_bytes, byteorder='big')
    kG = point_multiply((Gx, Gy), k)
    x1, _ = kG
    r = (e + x1) % n
    inv_1d = mod_inverse(1 + d, n)
    s = (inv_1d * (k - r * d)) % n
    
    # 攻击：伪造新消息的签名
    M_prime = M + b"_forged"
    e_prime_bytes = sm3_hash(Z + M_prime)
    e_prime = int.from_bytes(e_prime_bytes, byteorder='big')
    
    # 计算伪造的r'和s'
    r_prime = (r + e_prime - e) % n
    s_prime = (s + (r_prime - r) * inv_1d) % n
    
    # 验证伪造的签名是否有效
    P = point_multiply((Gx, Gy), d)  # 公钥
    valid = verify(P, M_prime, Z, r_prime, s_prime)
    
    return (r_prime, s_prime), valid

def scenario3_incorrect_Z(d: int, M: bytes, ID1: bytes, ID2: bytes) -> Tuple[Tuple[int, int], bool]:
    """
    场景3: 错误地使用相同的Z值处理不同ID
    攻击目标: 利用ID不同但Z值计算错误的漏洞伪造签名
    """
    P = point_multiply((Gx, Gy), d)  # 公钥
    
    # 正确计算Z1 (使用ID1)
    Z1 = calculate_z(ID1, P)
    
    # 对消息M使用ID1签名
    r, s = sign(d, M, Z1)
    
    # 攻击：使用错误的Z值（Z1）处理ID2
    Z2_correct = calculate_z(ID2, P)
    
    # 错误地使用Z1代替Z2进行验证
    invalid_verify = verify(P, M, Z1, r, s)  # 错误的验证方式
    valid_verify = verify(P, M, Z2_correct, r, s)  # 正确的验证方式
    
    # 攻击成功的条件：错误验证通过而正确验证失败
    success = invalid_verify and not valid_verify
    return (r, s), success

def scenario4_malleable_signature(P: Point, M: bytes, Z: bytes, r: int, s: int) -> Tuple[Tuple[int, int], bool]:
    """
    场景4: 签名可延展性攻击
    攻击目标: 从一个有效签名生成另一个有效签名
    """
    # 计算新的s' = -s - r mod n
    s_prime = (-s - r) % n
    
    # 验证新签名是否有效
    valid = verify(P, M, Z, r, s_prime)
    return (r, s_prime), valid

# 测试所有攻击场景
def test_misuse_scenarios():
    """测试SM2签名算法的各种误用场景"""
    # 生成密钥对
    d, P = generate_key_pair()
    print(f"私钥: {hex(d)}")
    print(f"公钥: ({hex(P[0])}, {hex(P[1])})")
    
    # 准备测试数据
    ID1 = b"user1@example.com"
    ID2 = b"user2@example.com"
    M1 = b"Original message 1"
    M2 = b"Original message 2"
    Z1 = calculate_z(ID1, P)
    Z2 = calculate_z(ID2, P)
    
    # 测试场景1: 重复使用随机数k
    print("\n=== 场景1: 重复使用随机数k ===")
    d_recovered, success = scenario1_reused_k(d, M1, M2, Z1, Z2)
    print(f"恢复的私钥: {hex(d_recovered)}")
    print(f"攻击成功: {'是' if success else '否'}")
    assert success, "场景1攻击失败"
    
    # 测试场景2: 使用固定的k
    print("\n=== 场景2: 使用固定的k ===")
    fixed_k = random.randint(2, n-2)
    forged_sig, valid = scenario2_fixed_k(d, M1, Z1, fixed_k)
    print(f"伪造的签名: r={hex(forged_sig[0])}, s={hex(forged_sig[1])}")
    print(f"伪造签名验证通过: {'是' if valid else '否'}")
    assert valid, "场景2攻击失败"
    
    # 测试场景3: 错误地使用相同的Z值
    print("\n=== 场景3: 错误使用Z值 ===")
    forged_sig, success = scenario3_incorrect_Z(d, M1, ID1, ID2)
    print(f"利用的签名: r={hex(forged_sig[0])}, s={hex(forged_sig[1])}")
    print(f"攻击成功: {'是' if success else '否'}")
    assert success, "场景3攻击失败"
    
    # 测试场景4: 签名可延展性
    print("\n=== 场景4: 签名可延展性 ===")
    r, s = sign(d, M1, Z1)
    print(f"原始签名: r={hex(r)}, s={hex(s)}")
    malleable_sig, valid = scenario4_malleable_signature(P, M1, Z1, r, s)
    print(f"变形后的签名: r={hex(malleable_sig[0])}, s={hex(malleable_sig[1])}")
    print(f"变形签名验证通过: {'是' if valid else '否'}")
    assert valid, "场景4攻击失败"
    
    print("\n所有误用场景测试通过!")

if __name__ == "__main__":
    test_misuse_scenarios()
