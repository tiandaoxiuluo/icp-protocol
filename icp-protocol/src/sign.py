#!/usr/bin/env python3
"""
trust-sign CLI
用法：
  python sign.py sign "内容"
  python sign.py verify <json文件路径>
  python sign.py keygen          生成新密钥对
"""
import json
import sys
import os
import base64
from datetime import datetime, timezone
from pathlib import Path

try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
except ImportError:
    print("需要安装 pycryptodome: pip install pycryptodome")
    sys.exit(1)

BASE_DIR = Path(os.environ.get("TRUST_BASE", r"C:\Users\liujiaqi\桌面\trust_statements"))
BASE_DIR.mkdir(parents=True, exist_ok=True)
KEY_FILE = BASE_DIR / "private_key.pem"
KEY_FINGERPRINT_FILE = BASE_DIR / "key_fingerprint.txt"

def load_or_generate_key():
    """加载已有私钥，没有则生成新的"""
    if KEY_FILE.exists():
        return KEY_FILE.read_text()
    else:
        key = RSA.generate(2048)
        private_pem = key.export_key()
        KEY_FILE.write_bytes(private_pem)
        fingerprint = SHA256.new(key.publickey().export_key()).hexdigest()
        KEY_FINGERPRINT_FILE.write_text(fingerprint)
        print(f"[trust-sign] 新密钥已生成，保存到 {KEY_FILE}", file=sys.stderr)
        print(f"[trust-sign] 公钥指纹: {fingerprint}", file=sys.stderr)
        return private_pem.decode()


def sign_content(content: str) -> dict:
    """签名内容，返回声明"""
    private_pem = load_or_generate_key()
    key = RSA.import_key(private_pem)
    public_pem = key.publickey().export_key()

    timestamp = datetime.now(timezone.utc).isoformat().replace("+00:00", "") + "Z"
    h = SHA256.new(content.encode("utf-8"))
    signature = pkcs1_15.new(key).sign(h)
    signature_b64 = base64.b64encode(signature).decode("utf-8")

    statement = {
        "protocol": "ICP-0.1",
        "content": content,
        "timestamp": timestamp,
        "signature": signature_b64,
        "public_key": public_pem.decode("utf-8")
    }
    return statement


def verify_statement(data: dict) -> dict:
    """验证声明"""
    try:
        content = data["content"]
        sig_b64 = data["signature"]
        pub_pem = data["public_key"]
        sig = base64.b64decode(sig_b64)
        pub_key = RSA.import_key(pub_pem)
        h = SHA256.new(content.encode("utf-8"))
        pkcs1_15.new(pub_key).verify(h, sig)
        return {
            "valid": True,
            "issuer_fingerprint": SHA256.new(pub_pem.encode()).hexdigest(),
            "message": "验证通过：内容未被篡改，签名有效"
        }
    except (ValueError, TypeError, KeyError) as e:
        return {
            "valid": False,
            "message": f"验证失败：{e}"
        }


def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "sign":
        if len(sys.argv) < 3:
            print("用法: python sign.py sign \"内容\"")
            sys.exit(1)
        content = sys.argv[2]
        stmt = sign_content(content)
        # 保存到文件
        ts = stmt["timestamp"].replace(":", "-").replace(".", "-")
        safe_name = content[:20].replace(" ", "_").replace("/", "_")
        out_file = BASE_DIR / f"stmt_{ts}_{safe_name}.json"
        out_file.write_text(json.dumps(stmt, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"[已保存] {out_file}")
        # 输出声明
        print(json.dumps(stmt, indent=2, ensure_ascii=False))

    elif cmd == "verify":
        if len(sys.argv) < 3:
            print("用法: python sign.py verify <json文件或JSON字符串>")
            sys.exit(1)
        arg = sys.argv[2]
        if os.path.isfile(arg):
            data = json.loads(Path(arg).read_text(encoding="utf-8"))
        else:
            data = json.loads(arg)
        result = verify_statement(data)
        print(json.dumps(result, indent=2, ensure_ascii=False))

    elif cmd == "keygen":
        key = RSA.generate(2048)
        private_pem = key.export_key()
        KEY_FILE.write_bytes(private_pem)
        fingerprint = SHA256.new(key.publickey().export_key()).hexdigest()
        KEY_FINGERPRINT_FILE.write_text(fingerprint)
        print(f"新密钥已生成: {KEY_FILE}")
        print(f"公钥指纹: {fingerprint}")

    else:
        print(f"未知命令: {cmd}")
        print(__doc__)
        sys.exit(1)


if __name__ == "__main__":
    main()
