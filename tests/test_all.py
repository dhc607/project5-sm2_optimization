#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
SM2算法完整测试套件
测试基础实现、优化实现、签名误用场景和签名伪造
"""

import unittest
import time
import random
from src.sm2_base import (
    generate_key_pair as generate_key_pair_base,
    sign as sign_base,
    verify as verify_base,
    calculate_z as calculate_z_base,
    point_add as point_add_base,
    point_multiply as point_multiply_base,
    Gx, Gy, n
)
from src.sm2_optimized import (
    generate_key_pair as generate_key_pair_opt,
    sign as sign_opt,
    verify as verify_opt,
    calculate_z as calculate_z_opt,
    point_add as point_add_opt,
    point_multiply as point_multiply_opt
)
from src.sm2_misuse import (
    scenario1_reused_k, scenario2_fixed_k,
    scenario3_incorrect_Z, scenario4_malleable_signature
)
from src.satoshi_forgery import (
    forge_satoshi_signature, verify_forgery, SATOSHI_PUBLIC_KEY
)

class TestSM2Base(unittest.TestCase):
    """测试SM2基础实现"""
    
    def test_key_generation(self):
        """测试密钥生成"""
        d, P = generate_key_pair_base()
        self.assertTrue(1 < d < n-1)
        self.assertIsNotNone(P)
        
        # 验证公钥是否在椭圆曲线上
        x, y = P
        left = (y * y) % p
        right = (x * x * x + a * x + b) % p
        self.assertEqual(left, right)
    
    def test_point_operations(self):
        """测试点运算"""
        P = (Gx, Gy)
        
        # 测试点加法
        Q = point_add_base(P, P)
        self.assertIsNotNone(Q)
        
        # 测试点乘法
        Q2 = point_multiply_base(P, 2)
        self.assertEqual(Q, Q2)
        
        # 测试分配律
        Q3 = point_multiply_base(P, 3)
        Q3_alt = point_add_base(P, Q2)
        self.assertEqual(Q3, Q3_alt)
    
    def test_sign_verify(self):
        """测试签名和验证"""
        d, P = generate_key_pair_base()
        user_id = b"test@example.com"
        message = b"Test message for SM2 signature"
        
        z = calculate_z_base(user_id, P)
        r, s = sign_base(d, message, z)
        
        # 验证有效签名
        self.assertTrue(verify_base(P, message, z, r, s))
        
        # 验证无效情况
        tampered_msg = b"Test message (tampered)"
        self.assertFalse(verify_base(P, tampered_msg, z, r, s))
        self.assertFalse(verify_base(P, message, z, (r+1)%n, s))
        self.assertFalse(verify_base(P, message, z, r, (s+1)%n))

class TestSM2Optimized(unittest.TestCase):
    """测试SM2优化实现"""
    
    def test_consistency(self):
        """测试与基础实现的一致性"""
        d, P = generate_key_pair_base()
        user_id = b"consistency@test.com"
        message = b"Consistency test message"
        
        # 测试Z值计算一致性
        z_base = calculate_z_base(user_id, P)
        z_opt = calculate_z_opt(user_id, P)
        self.assertEqual(z_base, z_opt)
        
        # 测试签名验证一致性
        r_base, s_base = sign_base(d, message, z_base)
        self.assertTrue(verify_opt(P, message, z_base, r_base, s_base))
        
        r_opt, s_opt = sign_opt(d, message, z_base)
        self.assertTrue(verify_base(P, message, z_base, r_opt, s_opt))
    
    def test_performance(self):
        """测试性能提升"""
        d, P = generate_key_pair_opt()
        user_id = b"performance@test.com"
        message = b"Performance test message"
        z = calculate_z_opt(user_id, P)
        r, s = sign_opt(d, message, z)
        
        # 测试签名性能
        start = time.time()
        for _ in range(100):
            sign_base(d, message, z)
        base_sign_time = time.time() - start
        
        start = time.time()
        for _ in range(100):
            sign_opt(d, message, z)
        opt_sign_time = time.time() - start
        
        self.assertLess(opt_sign_time, base_sign_time, "签名优化未生效")
        
        # 测试验证性能
        start = time.time()
        for _ in range(1000):
            verify_base(P, message, z, r, s)
        base_verify_time = time.time() - start
        
        start = time.time()
        for _ in range(1000):
            verify_opt(P, message, z, r, s)
        opt_verify_time = time.time() - start
        
        self.assertLess(opt_verify_time, base_verify_time, "验证优化未生效")

class TestSM2Misuse(unittest.TestCase):
    """测试SM2签名误用场景"""
    
    def setUp(self):
        self.d, self.P = generate_key_pair_opt()
        self.ID1 = b"user1@example.com"
        self.ID2 = b"user2@example.com"
        self.M1 = b"Test message 1"
        self.M2 = b"Test message 2"
        self.Z1 = calculate_z_opt(self.ID1, self.P)
        self.Z2 = calculate_z_opt(self.ID2, self.P)
    
    def test_scenario1(self):
        """测试重复使用随机数k"""
        d_recovered, success = scenario1_reused_k(self.d, self.M1, self.M2, self.Z1, self.Z2)
        self.assertTrue(success)
        self.assertEqual(d_recovered, self.d)
    
    def test_scenario2(self):
        """测试使用固定k"""
        fixed_k = random.randint(2, n-2)
        forged_sig, valid = scenario2_fixed_k(self.d, self.M1, self.Z1, fixed_k)
        self.assertTrue(valid)
    
    def test_scenario3(self):
        """测试错误使用Z值"""
        forged_sig, success = scenario3_incorrect_Z(self.d, self.M1, self.ID1, self.ID2)
        self.assertTrue(success)
    
    def test_scenario4(self):
        """测试签名可延展性"""
        r, s = sign_opt(self.d, self.M1, self.Z1)
        malleable_sig, valid = scenario4_malleable_signature(self.P, self.M1, self.Z1, r, s)
        self.assertTrue(valid)
        self.assertNotEqual(malleable_sig[1], s)

class TestSatoshiForgery(unittest.TestCase):
    """测试中本聪签名伪造"""
    
    def test_forgery(self):
        """测试签名伪造功能"""
        message = b"中本聪签名伪造测试"
        r, s, Z = forge_satoshi_signature(message, SATOSHI_PUBLIC_KEY)
        self.assertTrue(verify_forgery(message, Z, r, s, SATOSHI_PUBLIC_KEY))
        
        # 测试篡改消息后签名失效
        tampered_msg = b"中本聪签名伪造测试（已篡改）"
        self.assertFalse(verify_forgery(tampered_msg, Z, r, s, SATOSHI_PUBLIC_KEY))

# 全局变量（SM2参数）
p = 0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3
a = 0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498
b = 0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A

if __name__ == "__main__":
    unittest.main(verbosity=2)
