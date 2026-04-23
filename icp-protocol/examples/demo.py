#!/usr/bin/env python3
"""ICP 演示脚本"""
import json
from pathlib import Path
import sys

# 添加 src 目录到路径
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))
from sign import sign_content, verify_statement

def main():
    print("=" * 50)
    print("ICP - Information Credibility Protocol 演示")
    print("=" * 50)

    # 1. 签名
    message = "我确认这段文字由本人原创创作。"
    print(f"\n[1] 原始内容: {message}")
    statement = sign_content(message)
    print(f"[2] 签名成功，声明已生成")
    print(f"    协议: {statement['protocol']}")
    print(f"    时间: {statement['timestamp']}")
    print(f"    公钥指纹: {statement['public_key'][:30]}...")

    # 2. 验证
    print("\n[3] 开始验证...")
    result = verify_statement(statement)
    print(f"    结果: {result['message']}")

    # 3. 篡改测试
    tampered = statement.copy()
    tampered["content"] = "这句话被人改了！"
    print("\n[4] 篡改测试（修改内容后验证）...")
    result2 = verify_statement(tampered)
    print(f"    结果: {result2['message']}")

    print("\n" + "=" * 50)
    print("演示结束。了解更多请阅读 README.md")
    print("=" * 50)

if __name__ == "__main__":
    main()