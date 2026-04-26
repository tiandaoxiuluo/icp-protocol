#!/usr/bin/env python3
"""
Trust Kernel - 基于 ICP-0.1 升级的可信内容核验协议
支持：轨迹链、共识印章、时间胶囊

用法：
  python trust_kernel.py create "内容" [文件名]
  python trust_kernel.py amend "凭证包.json" "新内容"
  python trust_kernel.py witness "凭证包.json" "见证人名字" [公钥pem文件]
  python trust_kernel.py stamp  "凭证包.json"
  python trust_kernel.py verify "凭证包.json" [ots文件]
  python trust_kernel.py demo
"""
import json
import sys
import os
import base64
import hashlib
from datetime import datetime, timezone
from pathlib import Path

try:
    from Crypto.PublicKey import RSA
    from Crypto.Signature import pkcs1_15
    from Crypto.Hash import SHA256
except ImportError:
    print("需要安装 pycryptodome: pip install pycryptodome")
    sys.exit(1)

# ─── 路径配置 ───────────────────────────────────────────────
BASE_DIR = Path(os.environ.get(
    "TRUST_BASE",
    r"C:\Users\liujiaqi\桌面\trust_kernel_output"
))
BASE_DIR.mkdir(parents=True, exist_ok=True)
KEY_FILE = BASE_DIR / "private_key.pem"
KEY_FINGERPRINT_FILE = BASE_DIR / "key_fingerprint.txt"

# ─── 工具函数 ─────────────────────────────────────────────────
def _content_hash(content: str) -> str:
    return SHA256.new(content.encode("utf-8")).hexdigest()

def _node_hash(node: dict) -> str:
    """节点哈希 = hash(content_hash + timestamp + signature + prev_hash)"""
    s = (node.get("content_hash", "") +
         node.get("timestamp", "") +
         node.get("signature", "") +
         node.get("prev_hash", ""))
    return hashlib.sha256(s.encode()).hexdigest()

def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat().replace("+00:00", "") + "Z"

# ─── 密钥管理 ─────────────────────────────────────────────────
def load_or_generate_key():
    if KEY_FILE.exists():
        return KEY_FILE.read_text()
    key = RSA.generate(2048)
    private_pem = key.export_key()
    KEY_FILE.write_bytes(private_pem)
    fingerprint = SHA256.new(key.publickey().export_key()).hexdigest()
    KEY_FINGERPRINT_FILE.write_text(fingerprint)
    print(f"[Trust Kernel] 新密钥已生成: {KEY_FILE}", file=sys.stderr)
    print(f"[Trust Kernel] 公钥指纹: {fingerprint}", file=sys.stderr)
    return private_pem.decode()

def import_key(pem_str: str) -> RSA.RsaKey:
    return RSA.import_key(pem_str)

def sign_data(data_bytes: bytes, private_pem: str) -> str:
    key = RSA.import_key(private_pem)
    h = SHA256.new(data_bytes)
    sig = pkcs1_15.new(key).sign(h)
    return base64.b64encode(sig).decode()

def verify_signature(data_bytes: bytes, sig_b64: str, pub_pem: str) -> bool:
    try:
        sig = base64.b64decode(sig_b64)
        pub_key = RSA.import_key(pub_pem)
        h = SHA256.new(data_bytes)
        pkcs1_15.new(pub_key).verify(h, sig)
        return True
    except Exception:
        return False

# ─── 凭证包创建 ───────────────────────────────────────────────
def create_package(content: str, filename: str = None) -> dict:
    """创建新凭证包（创世节点）"""
    private_pem = load_or_generate_key()
    key = RSA.import_key(private_pem)
    public_pem = key.publickey().export_key().decode()
    fingerprint = SHA256.new(key.publickey().export_key()).hexdigest()

    timestamp = _utc_now()
    c_hash = _content_hash(content)

    # 对内容签名
    sig_data = content.encode("utf-8")
    sig_b64 = sign_data(sig_data, private_pem)

    genesis_node = {
        "content": content,
        "content_hash": c_hash,
        "timestamp": timestamp,
        "signature": sig_b64,
        "public_key": public_pem,
        "issuer_fingerprint": fingerprint,
        "prev_hash": "0" * 64,  # 创世节点 prev_hash 为全零
    }
    genesis_node["node_hash"] = _node_hash(genesis_node)

    package = {
        "protocol": "Trust Kernel 1.0",
        "content": content,
        "content_hash": c_hash,
        "genesis": genesis_node,
        "trail": [],          # 轨迹链节点列表
        "consensus_seals": [], # 见证人签名列表
        "time_capsule": None,  # 时间胶囊
        "created_at": timestamp,
        "last_modified": timestamp,
    }

    if filename:
        out = Path(filename)
    else:
        ts = timestamp.replace(":", "-").replace(".", "-")
        safe = content[:20].replace(" ", "_").replace("/", "_")
        out = BASE_DIR / f"tk_{ts}_{safe}.json"
    out.write_text(json.dumps(package, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[已创建] {out}")
    return package


# ─── 轨迹链追加 ──────────────────────────────────────────────
def amend_content(package: dict, new_content: str, save: bool = True) -> dict:
    """修改内容，自动追加轨迹节点"""
    private_pem = load_or_generate_key()
    key = RSA.import_key(private_pem)
    public_pem = key.publickey().export_key().decode()
    fingerprint = SHA256.new(key.publickey().export_key()).hexdigest()

    timestamp = _utc_now()
    c_hash = _content_hash(new_content)

    # 对新内容签名
    sig_data = new_content.encode("utf-8")
    sig_b64 = sign_data(sig_data, private_pem)

    # 获取上一个节点哈希（genesis 或 trail 最后一个）
    if package["trail"]:
        prev_hash = package["trail"][-1]["node_hash"]
    else:
        prev_hash = package["genesis"]["node_hash"]

    trail_node = {
        "content": new_content,
        "content_hash": c_hash,
        "timestamp": timestamp,
        "signature": sig_b64,
        "public_key": public_pem,
        "issuer_fingerprint": fingerprint,
        "prev_hash": prev_hash,
        "version": len(package["trail"]) + 2,  # v1=genesis, v2+=trail
    }
    trail_node["node_hash"] = _node_hash(trail_node)

    package["content"] = new_content
    package["content_hash"] = c_hash
    package["trail"].append(trail_node)
    package["last_modified"] = timestamp

    if save:
        _save_package(package)
        print(f"[轨迹追加] v{trail_node['version']} 节点已添加")

    return package


# ─── 共识印章 ─────────────────────────────────────────────────
def add_witness(package: dict, witness_name: str,
                pub_key_file: str = None,
                witness_private_pem: str = None,
                save: bool = True) -> dict:
    """
    添加见证人签名。
    若传入 witness_private_pem，直接用它签名；
    若传入 pub_key_file，加载其中的私钥签名（仅限测试）；
    否则为当前密钥仓的密钥签名。
    """
    if witness_private_pem:
        priv = witness_private_pem
    elif pub_key_file and Path(pub_key_file).exists():
        priv = Path(pub_key_file).read_text()
    else:
        priv = load_or_generate_key()

    key = RSA.import_key(priv)
    public_pem = key.publickey().export_key().decode()
    fingerprint = SHA256.new(key.publickey().export_key()).hexdigest()

    # 见证人对 content_hash 签名
    data_bytes = package["content_hash"].encode()
    sig_b64 = sign_data(data_bytes, priv)

    seal = {
        "witness": witness_name,
        "witness_fingerprint": fingerprint,
        "timestamp": _utc_now(),
        "signed_hash": package["content_hash"],
        "signature": sig_b64,
        "public_key": public_pem,
    }
    package["consensus_seals"].append(seal)

    if save:
        _save_package(package)
        print(f"[见证人] {witness_name} 已签署当前版本")

    return package


# ─── 时间胶囊（OpenTimestamps） ───────────────────────────────
def create_time_capsule(package: dict, save: bool = True) -> dict:
    """将内容哈希锚定到比特币区块链，生成 .ots 证明"""
    content_hash_hex = package["content_hash"]
    try:
        from opentimestamps.core.timestamp import Timestamp
        from opentimestamps.core.op import OpSHA256
        from opentimestamps.core.notary import PendingAttestation
        from opentimestamps.core.serialize import StreamSerializationContext
        import io

        data_bytes = bytes.fromhex(content_hash_hex)
        leaf = Timestamp(msg=data_bytes)
        sha_ts = leaf.ops.add(OpSHA256())
        sha_ts.attestations.add(PendingAttestation('https://a.btc.calendar.opentimestamps.org'))

        buf = io.BytesIO()
        leaf.serialize(StreamSerializationContext(buf))
        raw = buf.getvalue()

        package["time_capsule"] = {
            "status": "ots_created",
            "content_hash": content_hash_hex,
            "ots_file": base64.b64encode(raw).decode(),
            "created_at": _utc_now(),
            "note": ".ots file created. Submit to https://verify.opentimestamps.org/ "
                    "or run 'ots upgrade <file>' to anchor to Bitcoin blockchain.",
        }
    except ImportError:
        package["time_capsule"] = {
            "status": "missing_dependency",
            "content_hash": content_hash_hex,
            "local_timestamp": _utc_now(),
            "note": "pip install opentimestamps required",
        }
    except Exception as e:
        package["time_capsule"] = {
            "status": "error",
            "content_hash": content_hash_hex,
            "local_timestamp": _utc_now(),
            "error": str(e),
        }

    if save:
        _save_package(package)
    return package


# ─── 验证 ─────────────────────────────────────────────────────
def verify_package(package: dict, ots_bytes: bytes = None) -> dict:
    """全面验证凭证包，返回逐项结果"""
    results = {"overall": True, "checks": []}

    def check(name: str, passed: bool, detail: str = ""):
        results["checks"].append({"name": name, "passed": passed, "detail": detail})
        if not passed:
            results["overall"] = False

    # ── 协议版本 ──
    proto = package.get("protocol", "")
    check("Protocol Version", proto == "Trust Kernel 1.0",
          f"Found: {proto}")

    # ── Genesis 节点 ──
    g = package.get("genesis", {})
    check("Genesis Node Exists", bool(g), "No genesis node found")
    if not g:
        return results

    g_content = g.get("content", "")
    g_hash = _content_hash(g_content)
    g_sig = g.get("signature", "")
    g_pub = g.get("public_key", "")

    check("Genesis Content Hash",
          g_hash == g.get("content_hash", ""),
          f"Computed={g_hash[:16]}..., Stored={g.get('content_hash','')[:16]}...")

    genesis_sig_valid = verify_signature(g_content.encode(), g_sig, g_pub)
    check("Genesis Signature",
          genesis_sig_valid,
          "Genesis signature valid" if genesis_sig_valid else "Genesis signature invalid")

    check("Genesis prev_hash (all zeros for genesis)",
          g.get("prev_hash") == "0" * 64,
          f"Found={g.get('prev_hash')[:16]}...")

    check("Genesis node_hash Integrity",
          _node_hash(g) == g.get("node_hash", ""),
          f"Computed={_node_hash(g)[:16]}..., Stored={g.get('node_hash','')[:16]}...")

    # ── 轨迹链 ──
    trail = package.get("trail", [])
    expected_prev = g.get("node_hash", "")

    for i, node in enumerate(trail):
        idx = i + 1
        n_content = node.get("content", "")
        n_hash = _content_hash(n_content)
        n_sig = node.get("signature", "")
        n_pub = node.get("public_key", "")
        n_prev = node.get("prev_hash", "")

        check(f"Trail Node[{idx}] Content Hash",
              n_hash == node.get("content_hash", ""),
              f"Computed={n_hash[:16]}..., Stored={node.get('content_hash','')[:16]}...")

        trail_sig_valid = verify_signature(n_content.encode(), n_sig, n_pub)
        check(f"Trail Node[{idx}] Signature (Tamper Check)",
              trail_sig_valid,
              "Signature valid" if trail_sig_valid else "Signature invalid - content may be tampered")

        check(f"Trail Node[{idx}] Chain Link (prev_hash)",
              n_prev == expected_prev,
              f"Expected={expected_prev[:16]}..., Found={n_prev[:16]}...")

        check(f"Trail Node[{idx}] node_hash Integrity",
              _node_hash(node) == node.get("node_hash", ""),
              "Node hash mismatch")

        expected_prev = node.get("node_hash", "")

    # ── 当前内容签名验证（核心防篡改） ──
    if trail:
        last_node = trail[-1]
        current_sig_valid = verify_signature(
            package.get("content", "").encode(),
            last_node.get("signature", ""),
            last_node.get("public_key", "")
        )
    else:
        current_sig_valid = verify_signature(
            package.get("content", "").encode(),
            g_sig, g_pub
        )
    check("Current Content Signature (Tamper Detection)",
          current_sig_valid,
          "Current content signature valid" if current_sig_valid else "Current content signature invalid - content was tampered")

    # ── 当前内容哈希（与轨迹链终点一致） ──
    current_hash = _content_hash(package.get("content", ""))
    check("Current Content Hash (matches chain head)",
          current_hash == package.get("content_hash", ""),
          f"Computed={current_hash[:16]}..., Stored={package.get('content_hash','')[:16]}...")

    # ── 共识印章 ──
    seals = package.get("consensus_seals", [])
    for i, seal in enumerate(seals):
        sig_ok = verify_signature(
            seal.get("signed_hash", "").encode(),
            seal.get("signature", ""),
            seal.get("public_key", "")
        )
        check(f"Witness Seal[{i+1}]({seal.get('witness', '')})",
              sig_ok, f"Fingerprint={seal.get('witness_fingerprint', '')[:16]}...")

    # ── 时间胶囊 ──
    capsule = package.get("time_capsule")
    if capsule is not None:
        if capsule.get("ots_file"):
            try:
                import io
                from opentimestamps.core.serialize import StreamDeserializationContext
                from opentimestamps.core.timestamp import Timestamp
                ots_bytes = base64.b64decode(capsule["ots_file"])
                buf = io.BytesIO(ots_bytes)
                ts = Timestamp.deserialize(StreamDeserializationContext(buf),
                                           bytes.fromhex(capsule["content_hash"]))
                check("Time Capsule Deserialization", True,
                      f"msg={ts.msg.hex()[:16]}..., ops={len(ts.ops)}, att={len(ts.attestations)}")
            except Exception as e:
                check("Time Capsule Deserialization", False, str(e))
        else:
            check("Time Capsule Exists", False, "ots_file not found in capsule")

    return results


def print_verification(results: dict):
    """打印验证结果"""
    has_time_capsule_note = False
    print("\n" + "=" * 50)
    print("  Trust Kernel Verification Report")
    print("=" * 50)
    for c in results["checks"]:
        icon = "[PASS]" if c["passed"] else "[FAIL]"
        print(f"  {icon} {c['name']}")
        if c["detail"]:
            print(f"         -> {c['detail']}")
    print("-" * 50)
    if results["overall"]:
        print("  ALL CHECKS PASSED - credential package is trustworthy.")
    else:
        print("  WARNING: Some checks failed. See above.")
    print("=" * 50 + "\n")


# ─── 辅助 ─────────────────────────────────────────────────────
def _save_package(package: dict):
    ts = package.get("created_at", _utc_now()).replace(":", "-").replace(".", "-")
    safe = package.get("genesis", {}).get("content", "unknown")[:20].replace(" ", "_").replace("/", "_")
    out = BASE_DIR / f"tk_{ts}_{safe}.json"
    out.write_text(json.dumps(package, indent=2, ensure_ascii=False), encoding="utf-8")


def load_package(path: str) -> dict:
    return json.loads(Path(path).read_text(encoding="utf-8"))


# ─── CLI 入口 ──────────────────────────────────────────────────
def main():
    if len(sys.argv) < 2:
        print(__doc__)
        sys.exit(1)

    cmd = sys.argv[1].lower()

    if cmd == "create":
        content = sys.argv[2] if len(sys.argv) > 2 else input("输入内容: ")
        filename = sys.argv[3] if len(sys.argv) > 3 else None
        pkg = create_package(content, filename)
        print(json.dumps(pkg, indent=2, ensure_ascii=False))

    elif cmd == "amend":
        path = sys.argv[2]
        new_content = sys.argv[3] if len(sys.argv) > 3 else input("输入新内容: ")
        pkg = load_package(path)
        pkg = amend_content(pkg, new_content)
        print(json.dumps(pkg, indent=2, ensure_ascii=False))

    elif cmd == "witness":
        path = sys.argv[2]
        name = sys.argv[3] if len(sys.argv) > 3 else input("见证人名字: ")
        pub_file = sys.argv[4] if len(sys.argv) > 4 else None
        pkg = load_package(path)
        pkg = add_witness(pkg, name, pub_file)
        print(json.dumps(pkg, indent=2, ensure_ascii=False))

    elif cmd == "stamp":
        path = sys.argv[2]
        pkg = load_package(path)
        pkg = create_time_capsule(pkg)
        _save_package(pkg)
        print("[时间胶囊] 已保存到凭证包")
        print(f"[状态] {pkg['time_capsule']['status']}")

    elif cmd == "verify":
        path = sys.argv[2]
        ots_b64 = sys.argv[3] if len(sys.argv) > 3 else None
        pkg = load_package(path)
        ots_bytes = None
        if ots_b64 and os.path.isfile(ots_b64):
            ots_bytes = Path(ots_b64).read_bytes()
        elif ots_b64:
            try:
                ots_bytes = base64.b64decode(ots_b64)
            except Exception:
                pass
        # 检查时间胶囊是否为 None，若是则输出提示
        capsule = pkg.get("time_capsule")
        if capsule is None:
            print("[Note] No time capsule in package, skipping timestamp verification.")
        results = verify_package(pkg, ots_bytes)
        print_verification(results)

    elif cmd == "demo":
        demo_full_flow()

    else:
        print(f"未知命令: {cmd}")
        print(__doc__)
        sys.exit(1)


# ─── 完整流程演示 ─────────────────────────────────────────────
def demo_full_flow():
    print("\n" + "=" * 50)
    print("  Trust Kernel 完整流程演示")
    print("=" * 50)

    import tempfile
    tmpdir = Path(tempfile.mkdtemp())

    # 1. 创建内容
    print("\n[Step 1] 创建内容 → 生成凭证包")
    content_v1 = "这是 Trust Kernel 测试声明，版本 1。"
    pkg = create_package(content_v1, str(tmpdir / "demo_tk.json"))
    print(f"  内容: {content_v1}")
    print(f"  Genesis node_hash: {pkg['genesis']['node_hash'][:20]}...")

    # 2. 修改内容 → 轨迹追加
    print("\n[Step 2] 修改内容 → 自动追加轨迹节点")
    content_v2 = "这是 Trust Kernel 测试声明，版本 2，已更新。"
    pkg = amend_content(pkg, content_v2, save=True)
    print(f"  新内容: {content_v2}")
    print(f"  轨迹链节点数: {len(pkg['trail'])}")
    print(f"  trail[0] prev_hash: {pkg['trail'][0]['prev_hash'][:20]}...")
    print(f"  trail[0] node_hash: {pkg['trail'][0]['node_hash'][:20]}...")

    # 3. 添加见证人签名
    print("\n[Step 3] 添加见证人签名 → 共识印章")

    # 为演示生成两个独立的见证人密钥
    w1 = RSA.generate(2048)
    w2 = RSA.generate(2048)

    pkg = add_witness(pkg, "见证人Alice", witness_private_pem=w1.export_key().decode())
    pkg = add_witness(pkg, "见证人Bob",   witness_private_pem=w2.export_key().decode())
    print(f"  见证人数量: {len(pkg['consensus_seals'])}")
    for s in pkg["consensus_seals"]:
        print(f"    - {s['witness']}: {s['witness_fingerprint'][:20]}...")

    # 4. 生成时间胶囊
    print("\n[Step 4] 生成时间胶囊 → .ots 证明文件")
    pkg = create_time_capsule(pkg)
    cap = pkg["time_capsule"]
    print(f"  状态: {cap['status']}")
    if cap.get("ots_file"):
        print(f"  .ots 文件已嵌入凭证包 (base64, {len(cap['ots_file'])} 字符)")
    else:
        print(f"  本地时间戳: {cap.get('local_timestamp', 'N/A')}")

    # 保存最终凭证包
    out_json = tmpdir / "demo_tk_final.json"
    out_json.write_text(json.dumps(pkg, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\n  凭证包已保存: {out_json}")

    # 5. 验证
    print("\n[Step 5] 验证整个凭证包")
    results = verify_package(pkg)
    print_verification(results)

    # 额外测试：篡改检测（只改内容，不改签名）
    print("\n[Bonus] Tamper Detection Test")
    tampered = json.loads(out_json.read_text(encoding="utf-8"))
    tampered["content"] = "TAMPERED CONTENT AFTER SIGNING!!"
    # DO NOT update content_hash or any signature - verify should catch this
    results2 = verify_package(tampered)
    print_verification(results2)

    print(f"\n演示完毕。临时文件: {tmpdir}")


if __name__ == "__main__":
    main()