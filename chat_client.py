# chat_client.py
import json
import os
import socket
import threading

from rsa import rsa_encrypt
from aes_cbc_hmac import aes_encrypt, aes_decrypt

SERVER_HOST = "127.0.0.1"
SERVER_PORT = 19009

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

def recv_loop(sock, aes_key):
    buf = b""
    while True:
        msg, buf = recv_json_line(sock, buf)
        if msg is None:
            print("\n[-] Server disconnected.")
            os._exit(0)

        if msg.get("type") == "msg":
            try:
                plaintext = aes_decrypt(bytes.fromhex(msg["ct_hex"]), aes_key)
                print(f"\n{plaintext}\n> ", end="", flush=True)
            except ValueError:
                print("\n[!] Message integrity check failed (HMAC).")
        elif msg.get("type") == "err":
            print("\n[!] Server error:", msg.get("reason"))
            os._exit(0)

def send_loop(sock, aes_key):
    while True:
        text = input("> ").strip()
        if not text:
            continue
        ct = aes_encrypt(text, aes_key)
        send_json(sock, {"type": "msg", "ct_hex": ct.hex()})

def main():
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect((SERVER_HOST, SERVER_PORT))

        # 1) hello
        send_json(s, {"type": "hello"})

        # 2) 收公钥
        buf = b""
        msg, buf = recv_json_line(s, buf)
        if not msg or msg.get("type") != "pubkey":
            print("[-] failed to get pubkey")
            return
        e, n = msg["e"], msg["n"]

        # 3) 生成会话密钥并 RSA 加密发送
        aes_key = os.urandom(16)
        chunks = rsa_encrypt(aes_key, e, n)
        send_json(s, {"type": "key", "chunks": chunks})

        msg, buf = recv_json_line(s, buf)
        if not msg or msg.get("type") != "ok":
            print("[-] key exchange failed")
            return

        print("[+] Connected. You can chat now.")

        t_recv = threading.Thread(target=recv_loop, args=(s, aes_key), daemon=True)
        t_recv.start()

        send_loop(s, aes_key)

if __name__ == "__main__":
    main()