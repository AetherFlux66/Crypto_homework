# Secure TCP Chat (RSA Key Exchange + AES-CBC + HMAC)

一个最小可运行的 TCP 群聊示例：  
- 服务端启动后生成 RSA 密钥对，并向客户端下发公钥  
- 客户端随机生成 16 字节 AES 会话密钥，用 RSA 公钥加密后发给服务端  
- 后续消息使用 **AES-128 CBC** 加密，并对 `iv || ciphertext` 做 **HMAC-SHA256** 完整性校验  
- 服务端将收到的明文广播给其他在线客户端（按每个客户端自己的会话密钥重新加密）

---

## 文件结构

- `chat_server.py`：聊天服务端（生成 RSA 密钥对、处理握手、广播消息）  
- `chat_client.py`：聊天客户端（握手获取公钥、RSA 发送会话密钥、收发加密消息）  
- `rsa.py`：RSA 密钥生成、分块加解密（Miller-Rabin 素性检测 + 裸 RSA 分块）  
- `aes_cbc_hmac.py`：AES-128 CBC 加解密 + HMAC-SHA256（含 PKCS#7 填充）

---

## 环境要求

- Python 3.9+（建议 3.10/3.11）

本项目只依赖 Python 标准库，无需安装第三方包。

---

## 快速开始

### 1) 启动服务端

```bash
python chat_server.py
