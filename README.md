# SM2椭圆曲线密码算法实现与优化

## 功能说明

1. **SM2基础实现**：完整实现了SM2椭圆曲线密码算法的密钥生成、签名和验证功能
2. **优化实现**：通过预计算、窗口法等技术提升了算法性能
3. **签名误用验证**：实现了四种常见的SM2签名算法误用场景的攻击演示
4. **中本聪签名伪造**：演示如何在特定条件下伪造中本聪的数字签名

## 环境要求

- Python 3.7+
- 依赖库：
  - 对于Python 3.11+：无需额外库（已内置sm3）
  - 对于低版本Python：需要安装`gmssl`库

## 安装与使用

1. 克隆仓库：
   ```bash
   git clone https://github.com/你的用户名/sm2-experiment.git
   cd sm2-experiment
   ```

2. 安装依赖（如需要）：
   ```bash
   pip install -r requirements.txt
   ```

3. 运行测试：
   ```bash
   python -m unittest tests/test_all.py -v
   ```

4. 运行各个模块：
   ```bash
   # 测试基础实现
   python src/sm2_base.py
   
   # 测试优化实现性能
   python src/sm2_optimized.py
   
   # 测试签名误用场景
   python src/sm2_misuse.py
   
   # 测试中本聪签名伪造
   python src/satoshi_forgery.py
   ```

## 文档说明

- `docs/algorithm.md`：SM2算法的数学原理和详细推导
- `docs/misuse_analysis.md`：签名算法误用场景的详细分析和原理

