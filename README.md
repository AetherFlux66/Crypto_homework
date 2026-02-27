# Secure TCP Chat (RSA Key Exchange + AES-CBC + HMAC)

一个最小可运行的 TCP 聊天示例项目，演示“密钥交换 → 对称加密 → 完整性校验 → 广播转发”的完整链路：

- 服务端启动后生成 RSA 密钥对，并向客户端下发公钥
- 客户端随机生成 16 字节 AES 会话密钥，用 RSA 公钥加密后发给服务端
- 后续消息使用 **AES-128 CBC** 加密，并对 `iv || ciphertext` 做 **HMAC-SHA256** 完整性校验
- 服务端收到消息后解密成明文，再对其他在线客户端按各自会话密钥重新加密并广播


## 功能特性

- ✅ 多客户端连接，服务端广播转发
- ✅ 每个客户端独立 AES 会话密钥
- ✅ AES-CBC 加密 + HMAC-SHA256 完整性校验（防篡改）
- ✅ JSON 行协议（每条消息一行 JSON，易调试）
- ✅ 纯 Python 标准库实现（不依赖第三方包）

---

## 文件结构

```
.
├── chat_server.py      # 聊天服务端：RSA 密钥生成、握手、收发与广播
├── chat_client.py      # 聊天客户端：握手获取公钥、发送会话密钥、收发消息
├── rsa.py              # RSA：密钥生成、分块加解密、Miller-Rabin 素性检测
└── aes_cbc_hmac.py     # AES-128 CBC + HMAC-SHA256：加解密、PKCS#7 填充
```

---

## 环境要求

- Python 3.9+（建议 3.10/3.11）

本项目仅使用 Python 标准库，无需安装第三方依赖。

---

## 快速开始

### 启动服务端

在终端 1 运行：

```bash
python chat_server.py
```

### 聊天效果

客户端连接成功后会提示：

```
[+] Connected. You can chat now.
>
```

输入文本回车即可发送，其他客户端会收到类似：

```
[] hello world
```

---

## 协议说明

客户端与服务端使用 **JSON 行协议**：每条消息是一个 JSON 对象，并以 `\n` 结尾分隔。

### 1) 握手阶段

1. Client -> Server
```json
{"type":"hello"}
```

2. Server -> Client（下发 RSA 公钥）
```json
{"type":"pubkey","e":65537,"n":123456789...}
```

3. Client -> Server（发送 AES 会话密钥：RSA 分块加密）
```json
{"type":"key","chunks":[111...,222...,333...]}
```

4. Server -> Client（确认）
```json
{"type":"ok"}
```

### 2) 消息阶段

- Client -> Server
```json
{"type":"msg","ct_hex":"..."}
```

- Server -> Client（广播给其他客户端）
```json
{"type":"msg","ct_hex":"..."}
```

---

## 数据格式

`ct_hex` 为十六进制字符串，对应二进制结构为：

```
iv (16 bytes) || ciphertext (multiple of 16 bytes) || tag (32 bytes)
```

其中：
- `iv`：AES-CBC 初始化向量（16 字节）
- `ciphertext`：AES-CBC 密文（长度为 16 的倍数）
- `tag`：HMAC-SHA256 输出（32 字节），通常对 `iv || ciphertext` 计算

---

## 安全说明

这个项目主要用于学习“加密通信的组成模块”，但它不是安全的生产实现：

- **RSA 未使用安全填充（OAEP/PKCS#1）**：裸 RSA/简单分块并不满足现代安全要求
- **缺少身份认证**：客户端无法确认拿到的公钥一定来自真实服务端，存在中间人攻击风险
- **建议生产方案**：直接使用 TLS（例如 Python `ssl` + `socket`）或成熟加密库（如 `cryptography` / libsodium）

尽管如此，本项目仍展示了两个关键概念：
- **机密性（Confidentiality）**：AES-CBC 负责加密
- **完整性（Integrity）**：HMAC-SHA256 负责防篡改（校验失败应拒绝/断开）
