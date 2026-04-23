# ICP - Information Credibility Protocol

> 在AI可以生成一切的时代，为人类创作的内容提供密码学级别的"可信证明"。

[![Protocol Version](https://img.shields.io/badge/Protocol-ICP--0.1-blue)](https://github.com/yourusername/icp-protocol)
[![License: CC BY 4.0](https://img.shields.io/badge/License-CC%20BY%204.0-lightgrey)](https://creativecommons.org/licenses/by/4.0/)

## 🎯 是什么？

ICP（信息可信协议）是一个极简的开放标准，用RSA-SHA256数字签名让任何人都能验证一段文字是否：
- **原创**：由持有私钥的人创作
- **完整**：内容未被篡改
- **有时限**：有时间戳证明发布时间

## 📦 安装

```bash
pip install pycryptodome
```

## 🚀 快速开始

### 签名（生成可信声明）

```python
from trust_engine import TrustEngine

engine = TrustEngine()
statement = engine.sign("这是我亲手写的内容，不是AI生成的。")
print(statement)
```

### 验证（验证可信声明）

```python
from trust_engine import TrustEngine

engine = TrustEngine()
result = engine.verify(statement)
print(result["message"])
```

### 命令行

```bash
python src/sign.py sign "你的内容"
python src/sign.py verify <声明.json>
```

## 🔬 技术规范

- **签名算法**：RSA-2048 + SHA-256 (PKCS#1 v1.5)
- **声明格式**：JSON
- **协议版本**：ICP-0.1
- **依赖**：pycryptodome

详见 [ICP-RFC-draft.md](docs/ICP-RFC-draft.md)

## 📂 项目结构

```
icp-protocol/
├── src/
│   └── sign.py          # 签名引擎
├── docs/
│   ├── ICP-RFC-draft.md # 技术规范（RFC格式）
│   └── manifesto.md    # 宣言文章
├── examples/
│   └── demo.py          # 使用演示
├── icp.py               # 原始原型
├── README.md
└── LICENSE
```

## 📄 文档

- [RFC草案（技术规范）](docs/ICP-RFC-draft.md)
- [宣言文章](docs/manifesto.md)

## 🤝 参与贡献

这是一个开放协议，任何人都可以使用和改进。

1. Fork 本仓库
2. 提出 Issue 或 Pull Request
3. 讨论协议改进

## ⚠️ 安全提示

- 妥善保管你的私钥！丢失后无法恢复。
- 私钥泄露后应立即生成新密钥对。
- 当前使用RSA-2048，量子计算时代需升级到后量子算法。

## 📜 许可证

本协议内容采用 [CC BY 4.0](https://creativecommons.org/licenses/by/4.0/) 许可证。
代码采用 [MIT License](LICENSE)。

---

🦞 *龙虾为你签名*