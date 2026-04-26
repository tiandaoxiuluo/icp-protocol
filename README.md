# ICP-Protocol (Information Credibility Protocol)

> In an era where AI can generate anything, we provide cryptographically verifiable proof of authenticity for human-created content.
>
> 在AI可以生成一切的时代，为人类创作的内容提供密码学级别的“可信证明”。

[English](#english) | [中文](#中文)

---

## English

### What is this?

ICP is a minimal open protocol that uses RSA digital signatures to create unforgeable "trust statements" for any piece of content. Anyone can verify the authenticity of a statement independently — no platform, no authority, no human review required.

**Trust math. Nothing else.**

### Quick Start

```bash
# Sign content
python icp.py sign "Your message here"

# Verify a statement
python icp.py verify statement.json
Author
@tiandaoxiuluo


## 🧬 Trust Kernel Upgrade

ICP has been upgraded to **Trust Kernel**, adding three core capabilities:

- **Creation Trail** — Every edit is automatically recorded. All versions are chained into an immutable history.
- **Consensus Seal** — Multiple witnesses can sign and verify the same content. Who witnessed and when is fully traceable.
- **Time Capsule** — Built-in OpenTimestamps support. Users can anchor content hashes to the Bitcoin blockchain or any compatible public calendar server as needed.

### Usage
```bash
# Create a new credential package
python trust_kernel.py create "Your content here"

# Verify a credential package
python trust_kernel.py verify package.json
