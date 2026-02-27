# chat_server.py
import json
import socket
import threading

from rsa import generate_rsa_keypair, rsa_decrypt  # 你上传的 rsa.py 里有这些函数
from aes_cbc_hmac import aes_encrypt, aes_decrypt  # 使用 CBC+HMAC 版本

HOST = "0.0.0.0"
PORT = 19009

clients_lock = threading.Lock()
# conn -> {"addr": addr, "key": aes_key_bytes}
clients = {}

def send_json(conn, obj):
    conn.sendall((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))

def recv_json_line(conn, buf):
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None, buf
        buf += chunk
    line, buf = buf.split(b"\n", 1)
    return json.loads(line.decode("utf-8")), buf

def broadcast(sender_conn, sender_addr, plaintext: str):
    """把明文广播给所有其他在线客户端（按各自会话密钥重新加密）"""
    with clients_lock:
        items = list(clients.items())

    for conn, info in items:
        if conn is sender_conn:
            continue
        try:
            ct = aes_encrypt(f"[{sender_addr[0]}:{sender_addr[1]}] {plaintext}", info["key"])
            send_json(conn, {"type": "msg", "ct_hex": ct.hex()})
        except Exception:
            # 发不出去就忽略（也可以做清理）
            pass

def handle_client(conn, addr, rsa_d, rsa_n, rsa_e):
    buf = b""
    aes_key = None

    try:
        # 1) hello
        msg, buf = recv_json_line(conn, buf)
        if not msg or msg.get("type") != "hello":
            return

        # 2) 发公钥
        send_json(conn, {"type": "pubkey", "e": rsa_e, "n": rsa_n})

        # 3) 收会话密钥（RSA 加密后的 chunks）
        msg, buf = recv_json_line(conn, buf)
        if not msg or msg.get("type") != "key":
            return

        chunks = msg["chunks"]
        aes_key = rsa_decrypt(chunks, rsa_d, rsa_n)
        if len(aes_key) != 16:
            return

        with clients_lock:
            clients[conn] = {"addr": addr, "key": aes_key}

        send_json(conn, {"type": "ok"})
        broadcast(conn, addr, "上线了")

        # 4) 收消息并广播
        while True:
            msg, buf = recv_json_line(conn, buf)
            if msg is None:
                break
            if msg.get("type") != "msg":
                continue

            try:
                plaintext = aes_decrypt(bytes.fromhex(msg["ct_hex"]), aes_key)
            except ValueError:
                # HMAC 校验失败（篡改/乱包/密钥不一致）
                send_json(conn, {"type": "err", "reason": "HMAC verification failed"})
                break

            broadcast(conn, addr, plaintext)

    finally:
        with clients_lock:
            info = clients.pop(conn, None)
        try:
            conn.close()
        except Exception:
            pass
        if info:
            broadcast(None, info["addr"], "下线了")

def main():
    rsa_e, rsa_d, rsa_n, p, q = generate_rsa_keypair(bits=1024)

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind((HOST, PORT))
        s.listen(50)
        print(f"[*] Listening on {HOST}:{PORT}")

        while True:
            conn, addr = s.accept()
            print(f"[+] Connected: {addr}")
            t = threading.Thread(target=handle_client, args=(conn, addr, rsa_d, rsa_n, rsa_e), daemon=True)
            t.start()

if __name__ == "__main__":
    main()