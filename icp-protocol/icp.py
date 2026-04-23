import json
import base64
from datetime import datetime
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256

class TrustEngine:
    """信息可信度引擎（最简原型）"""
    
    def __init__(self):
        self.private_key = None
        self.public_key = None

    # ------------------ 1. 签名 ------------------
    def sign(self, content: str, private_pem: str = None) -> dict:
        """
        对内容进行数字签名，返回一个可信声明
        """
        # 如果没有现成的私钥，就自动生成一对新的
        if private_pem is None:
            key = RSA.generate(2048)
            self.private_key = key.export_key()
            self.public_key = key.publickey().export_key()
        else:
            self.private_key = private_pem
            key = RSA.import_key(private_pem)
            self.public_key = key.publickey().export_key()

        timestamp = datetime.utcnow().isoformat() + "Z"
        
        # 计算签名
        h = SHA256.new(content.encode('utf-8'))
        signature = pkcs1_15.new(key).sign(h)
        signature_b64 = base64.b64encode(signature).decode('utf-8')
        
        # 打包声明
        statement = {
            "protocol": "ICP-0.1",
            "content": content,
            "timestamp": timestamp,
            "signature": signature_b64,
            "public_key": self.public_key.decode('utf-8')
        }
        return statement

    # ------------------ 2. 验证 ------------------
    def verify(self, statement: dict) -> dict:
        """
        验证一个可信声明是否被篡改，或是否为伪造
        """
        try:
            content = statement["content"]
            signature_b64 = statement["signature"]
            public_pem = statement["public_key"]
            
            signature = base64.b64decode(signature_b64)
            public_key = RSA.import_key(public_pem)
            h = SHA256.new(content.encode('utf-8'))
            
            pkcs1_15.new(public_key).verify(h, signature)
            
            return {
                "valid": True,
                "issuer_public_key_fingerprint": SHA256.new(public_pem.encode()).hexdigest(),
                "message": "✅ 验证通过：内容未被篡改，签名有效。"
            }
        except (ValueError, TypeError):
            return {
                "valid": False,
                "message": "❌ 验证失败：内容被篡改或签名无效。"
            }

# ------------------ 使用演示 ------------------
if __name__ == "__main__":
    engine = TrustEngine()
    
    # 你写了一段话，签名
    message = "我，张三，确认这篇文章由本人创作，未经AI自动生成。"
    signed_statement = engine.sign(message)
    
    print("====== 可信声明 ======")
    print(json.dumps(signed_statement, indent=2, ensure_ascii=False))
    
    # 任何人拿到这个声明，验证真伪
    print("\n====== 验证结果 ======")
    result = engine.verify(signed_statement)
    print(result["message"])
    
    # 如果有人篡改了内容……
    tampered_statement = signed_statement.copy()
    tampered_statement["content"] = "这句话被人改过了！"
    print("\n====== 验证篡改后的声明 ======")
    result = engine.verify(tampered_statement)
    print(result["message"])