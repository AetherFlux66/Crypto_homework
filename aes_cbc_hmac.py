# ======================
# 1. AES 所需常量与表
# ======================
import string
import random
import sys
import time
import os
import hmac
import hashlib

S_BOX = [
    [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76],
    [0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0],
    [0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15],
    [0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75],
    [0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84],
    [0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF],
    [0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8],
    [0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2],
    [0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73],
    [0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB],
    [0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79],
    [0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08],
    [0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A],
    [0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E],
    [0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF],
    [0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
]

INV_S_BOX = [
    [0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB],
    [0x7C, 0xE3, 0x39, 0x82, 0x9B, 0x2F, 0xFF, 0x87, 0x34, 0x8E, 0x43, 0x44, 0xC4, 0xDE, 0xE9, 0xCB],
    [0x54, 0x7B, 0x94, 0x32, 0xA6, 0xC2, 0x23, 0x3D, 0xEE, 0x4C, 0x95, 0x0B, 0x42, 0xFA, 0xC3, 0x4E],
    [0x08, 0x2E, 0xA1, 0x66, 0x28, 0xD9, 0x24, 0xB2, 0x76, 0x5B, 0xA2, 0x49, 0x6D, 0x8B, 0xD1, 0x25],
    [0x72, 0xF8, 0xF6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xD4, 0xA4, 0x5C, 0xCC, 0x5D, 0x65, 0xB6, 0x92],
    [0x6C, 0x70, 0x48, 0x50, 0xFD, 0xED, 0xB9, 0xDA, 0x5E, 0x15, 0x46, 0x57, 0xA7, 0x8D, 0x9D, 0x84],
    [0x90, 0xD8, 0xAB, 0x00, 0x8C, 0xBC, 0xD3, 0x0A, 0xF7, 0xE4, 0x58, 0x05, 0xB8, 0xB3, 0x45, 0x06],
    [0xD0, 0x2C, 0x1E, 0x8F, 0xCA, 0x3F, 0x0F, 0x02, 0xC1, 0xAF, 0xBD, 0x03, 0x01, 0x13, 0x8A, 0x6B],
    [0x3A, 0x91, 0x11, 0x41, 0x4F, 0x67, 0xDC, 0xEA, 0x97, 0xF2, 0xCF, 0xCE, 0xF0, 0xB4, 0xE6, 0x73],
    [0x96, 0xAC, 0x74, 0x22, 0xE7, 0xAD, 0x35, 0x85, 0xE2, 0xF9, 0x37, 0xE8, 0x1C, 0x75, 0xDF, 0x6E],
    [0x47, 0xF1, 0x1A, 0x71, 0x1D, 0x29, 0xC5, 0x89, 0x6F, 0xB7, 0x62, 0x0E, 0xAA, 0x18, 0xBE, 0x1B],
    [0xFC, 0x56, 0x3E, 0x4B, 0xC6, 0xD2, 0x79, 0x20, 0x9A, 0xDB, 0xC0, 0xFE, 0x78, 0xCD, 0x5A, 0xF4],
    [0x1F, 0xDD, 0xA8, 0x33, 0x88, 0x07, 0xC7, 0x31, 0xB1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xEC, 0x5F],
    [0x60, 0x51, 0x7F, 0xA9, 0x19, 0xB5, 0x4A, 0x0D, 0x2D, 0xE5, 0x7A, 0x9F, 0x93, 0xC9, 0x9C, 0xEF],
    [0xA0, 0xE0, 0x3B, 0x4D, 0xAE, 0x2A, 0xF5, 0xB0, 0xC8, 0xEB, 0xBB, 0x3C, 0x83, 0x53, 0x99, 0x61],
    [0x17, 0x2B, 0x04, 0x7E, 0xBA, 0x77, 0xD6, 0x26, 0xE1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0C, 0x7D]
]

RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# ======================
# 2. 加解密共用的子函数
# ======================
def rot_word(word):
    """对 4 字节（word）循环左移 1 字节"""
    return word[1:] + word[:1]

def sub_word(word):
    """使用 AES S-Box 替换 4 字节"""
    return [S_BOX[b >> 4][b & 0x0F] for b in word]

def inv_sub_word(word):
    """使用 AES 逆 S-Box 替换 4 字节"""
    return [INV_S_BOX[b >> 4][b & 0x0F] for b in word]

def xtime(a):
    """有限域 GF(2^8) 中计算 2*a，并限制在 8 位"""
    return ((a << 1) ^ 0x1B) if (a & 0x80) else (a << 1)

def key_expansion(key: bytes):
    """
    对 128 位的主密钥进行扩展，生成 176 字节(4*(10+1)=44个 word) 的所有轮密钥。
    返回的一维数组 expanded_key 共 176 个字节，每 16 字节对应 AES 的一个 round key。
    """
    assert len(key) == 16, "AES-128 密钥长度必须是 16 字节"
    Nk = 4     # 4 word
    Nr = 10    # 10 轮
    Nb = 4     # 每轮4个 word

    # 前 16 字节切分成 4 个 word
    w = [list(key[i:i+4]) for i in range(0, 16, 4)]

    for i in range(Nk, Nb * (Nr + 1)):
        temp = w[i - 1]
        if i % Nk == 0:
            temp = sub_word(rot_word(temp))
            # RCON 只异或 temp[0]
            temp[0] ^= RCON[(i // Nk) - 1]
        w.append([w[i - Nk][j] ^ temp[j] for j in range(4)])

    expanded_key = [byte for word in w for byte in word]  # 扁平化 => 176字节
    return expanded_key

# ======================
# 3. 加密端
# ======================
def sub_bytes(state):
    """对 4x4 的状态矩阵进行逐字节 S-Box"""
    return [[S_BOX[byte >> 4][byte & 0x0F] for byte in row] for row in state]

def shift_rows(state):
    """
    行移位：
    - 第 0 行不动
    - 第 1 行左移 1
    - 第 2 行左移 2
    - 第 3 行左移 3
    """
    return [
        [state[0][0], state[0][1], state[0][2], state[0][3]],
        [state[1][1], state[1][2], state[1][3], state[1][0]],
        [state[2][2], state[2][3], state[2][0], state[2][1]],
        [state[3][3], state[3][0], state[3][1], state[3][2]],
    ]

def add_round_key(state, round_key):
    """将 16 字节的子密钥与 state(4x4) 逐字节异或"""
    # 先把 round_key(一维) 变成 4x4
    rk_matrix = [[round_key[row + col*4] for col in range(4)] for row in range(4)]
    return [[state[r][c] ^ rk_matrix[r][c] for c in range(4)] for r in range(4)]

def mix_columns(state):
    """
    MixColumns: 把每一列当作多项式与固定的常数矩阵相乘（在 GF(2^8) 上）。
    该变换只在前 9 轮出现，最后一轮不做。
    """
    def mix_single_column(column):
        a0, a1, a2, a3 = column
        # 2·a0 ⊕ 3·a1 ⊕ 1·a2 ⊕ 1·a3
        b0 = (xtime(a0) ^ (xtime(a1) ^ a1) ^ a2 ^ a3) & 0xFF
        # 1·a0 ⊕ 2·a1 ⊕ 3·a2 ⊕ 1·a3
        b1 = (a0 ^ xtime(a1) ^ (xtime(a2) ^ a2) ^ a3) & 0xFF
        # 1·a0 ⊕ 1·a1 ⊕ 2·a2 ⊕ 3·a3
        b2 = (a0 ^ a1 ^ xtime(a2) ^ (xtime(a3) ^ a3)) & 0xFF
        # 3·a0 ⊕ 1·a1 ⊕ 1·a2 ⊕ 2·a3
        b3 = ((xtime(a0) ^ a0) ^ a1 ^ a2 ^ xtime(a3)) & 0xFF
        return [b0, b1, b2, b3]

    new_state = [[0]*4 for _ in range(4)]
    for col in range(4):
        mc = mix_single_column([state[row][col] for row in range(4)])
        for row in range(4):
            new_state[row][col] = mc[row]
    return new_state

def pad(plaintext_bytes: bytes):
    """PKCS#7 填充明文"""
    padding_len = 16 - (len(plaintext_bytes) % 16)
    return plaintext_bytes + bytes([padding_len] * padding_len)

def split_blocks(data: bytes):
    """每 16 字节分成一块"""
    return [data[i:i+16] for i in range(0, len(data), 16)]

def _aes_encrypt_block(block16: bytes, expanded_key: list[int]) -> bytes:
    """加密单个 16 字节分组（AES-128），供 CBC 调用。"""
    assert len(block16) == 16
    # 转成 4x4 矩阵（列优先）
    state = [[block16[r + 4*c] for c in range(4)] for r in range(4)]

    # 初始 AddRoundKey (Round 0)
    state = add_round_key(state, expanded_key[0:16])

    # 中间 9 轮 (Round 1 ~ 9)
    for round_idx in range(1, 10):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        rk = expanded_key[round_idx*16 : (round_idx+1)*16]
        state = add_round_key(state, rk)

    # 最后一轮 (Round 10)
    state = sub_bytes(state)
    state = shift_rows(state)
    rk_final = expanded_key[160:176]  # round 10 的 key
    state = add_round_key(state, rk_final)

    out = bytearray()
    for c in range(4):
        for r in range(4):
            out.append(state[r][c])
    return bytes(out)


def _derive_hmac_key(aes_key: bytes) -> bytes:
    """从 AES 会话密钥派生一个 HMAC 密钥（最小实现，演示用途）。"""
    # HMAC-SHA256 的 key 长度不限，这里用 SHA256 派生 32 字节
    return hashlib.sha256(b"auth|" + aes_key).digest()


def aes_encrypt(plaintext: str, key: bytes) -> bytes:
    """
    AES-128 CBC + HMAC-SHA256 (最小实现，演示用途)

    输入:
      - plaintext: 待加密的字符串(会用 UTF-8 编码)
      - key: 16字节主密钥
    输出(二进制):
      - iv(16) || ciphertext(N*16) || tag(32)

    说明：
      - CBC 的 IV 每次随机生成
      - tag = HMAC-SHA256( iv || ciphertext )
    """
    assert len(key) == 16, "AES-128 密钥长度必须是 16 字节"

    plaintext_bytes = plaintext.encode("utf-8")
    padded = pad(plaintext_bytes)
    blocks = split_blocks(padded)

    expanded_key = key_expansion(key)

    iv = os.urandom(16)
    prev = iv

    ct = bytearray()
    for block in blocks:
        x = bytes([b ^ p for b, p in zip(block, prev)])
        c = _aes_encrypt_block(x, expanded_key)
        ct.extend(c)
        prev = c

    hmac_key = _derive_hmac_key(key)
    tag = hmac.new(hmac_key, iv + bytes(ct), hashlib.sha256).digest()

    return iv + bytes(ct) + tag

# ======================
# 4. 解密端
# ======================
def inv_shift_rows(state):
    """
    解密时的逆行移位：
    - 第 0 行不动
    - 第 1 行右移 1
    - 第 2 行右移 2
    - 第 3 行右移 3
    """
    return [
        [state[0][0], state[0][1], state[0][2], state[0][3]],
        [state[1][3], state[1][0], state[1][1], state[1][2]],
        [state[2][2], state[2][3], state[2][0], state[2][1]],
        [state[3][1], state[3][2], state[3][3], state[3][0]],
    ]

def inv_sub_bytes(state):
    """对 4x4 的状态矩阵使用逆 S-Box"""
    return [[INV_S_BOX[byte >> 4][byte & 0x0F] for byte in row] for row in state]

def inv_mix_columns(state):
    """
    逆 MixColumns：把每一列与逆矩阵相乘（在 GF(2^8) 上）。
    """
    def inv_mix_single_column(column):
        a0, a1, a2, a3 = column
        # 逆 MixColumns 的多项式系数是 0x0E, 0x0B, 0x0D, 0x09
        # b0 = 14·a0 ⊕ 11·a1 ⊕ 13·a2 ⊕ 9·a3
        b0 = (mul(a0, 0x0E) ^ mul(a1, 0x0B) ^ mul(a2, 0x0D) ^ mul(a3, 0x09)) & 0xFF
        # b1 = 9·a0  ⊕ 14·a1 ⊕ 11·a2 ⊕ 13·a3
        b1 = (mul(a0, 0x09) ^ mul(a1, 0x0E) ^ mul(a2, 0x0B) ^ mul(a3, 0x0D)) & 0xFF
        # b2 = 13·a0 ⊕ 9·a1  ⊕ 14·a2 ⊕ 11·a3
        b2 = (mul(a0, 0x0D) ^ mul(a1, 0x09) ^ mul(a2, 0x0E) ^ mul(a3, 0x0B)) & 0xFF
        # b3 = 11·a0 ⊕ 13·a1 ⊕ 9·a2  ⊕ 14·a3
        b3 = (mul(a0, 0x0B) ^ mul(a1, 0x0D) ^ mul(a2, 0x09) ^ mul(a3, 0x0E)) & 0xFF
        return [b0, b1, b2, b3]

    def mul(a, b):
        """
        在 GF(2^8) 上进行 a×b，多次 xtime 操作的简写。
        """
        r = 0
        for _ in range(8):
            if (b & 1) == 1:
                r ^= a
            hi = a & 0x80
            a <<= 1
            if hi:
                a ^= 0x1B
            a &= 0xFF
            b >>= 1
        return r & 0xFF

    new_state = [[0]*4 for _ in range(4)]
    for col in range(4):
        cdata = [state[row][col] for row in range(4)]
        mc = inv_mix_single_column(cdata)
        for row in range(4):
            new_state[row][col] = mc[row]
    return new_state

def unpad(data: bytes) -> bytes:
    """
    PKCS#7 去填充：取最后一个字节 n，检查倒数 n 个字节是否都为 n
    """
    if not data:
        return data
    pad_len = data[-1]
    # 安全起见做一下基本检查
    if pad_len < 1 or pad_len > 16:
        return data  # 或者抛异常
    if data[-pad_len:] != bytes([pad_len]*pad_len):
        return data  # 或者抛异常
    return data[:-pad_len]

def _aes_decrypt_block(block16: bytes, expanded_key: list[int]) -> bytes:
    """解密单个 16 字节分组（AES-128），供 CBC 调用。"""
    assert len(block16) == 16
    state = [[block16[r + 4*c] for c in range(4)] for r in range(4)]

    # 先 AddRoundKey (使用最后一轮子密钥 Round 10)
    state = add_round_key(state, expanded_key[160:176])

    # 逆最后一轮 (没有 inv_mix_columns)
    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)

    # 逆 9 轮 (Round 9 ~ Round 1)
    for round_idx in range(9, 0, -1):
        rk = expanded_key[round_idx*16 : (round_idx+1)*16]
        state = add_round_key(state, rk)
        state = inv_mix_columns(state)
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)

    # 最后再加一次 Round 0 的子密钥
    state = add_round_key(state, expanded_key[0:16])

    out = bytearray()
    for c in range(4):
        for r in range(4):
            out.append(state[r][c])
    return bytes(out)


def aes_decrypt(ciphertext: bytes, key: bytes) -> str:
    """
    AES-128 CBC + HMAC-SHA256 (最小实现，演示用途)

    输入:
      - ciphertext: iv(16) || ciphertext(N*16) || tag(32)
      - key: 16字节主密钥
    输出:
      - 解密后的明文(字符串,UTF-8)

    校验：
      - 先验证 tag = HMAC-SHA256(iv || ciphertext_body)
      - tag 校验失败直接抛 ValueError
    """
    assert len(key) == 16, "AES-128 密钥长度必须是 16 字节"
    if len(ciphertext) < 16 + 32:
        raise ValueError("ciphertext too short")

    iv = ciphertext[:16]
    tag = ciphertext[-32:]
    ct_body = ciphertext[16:-32]

    if len(ct_body) % 16 != 0:
        raise ValueError("ciphertext body not multiple of block size")

    hmac_key = _derive_hmac_key(key)
    expected = hmac.new(hmac_key, iv + ct_body, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("HMAC verification failed")

    expanded_key = key_expansion(key)

    prev = iv
    plaintext_bytes = bytearray()

    for block in split_blocks(ct_body):
        d = _aes_decrypt_block(block, expanded_key)
        p = bytes([b ^ pv for b, pv in zip(d, prev)])
        plaintext_bytes.extend(p)
        prev = block

    unpadded = unpad(bytes(plaintext_bytes))
    return unpadded.decode("utf-8", errors="ignore")

def random_string(length: int) -> str:
    """
    生成指定长度的随机字符串，包含大小写字母和数字。
    """
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def test_aes_performance(key: bytes, trials=10, max_len=16):
    """
    测试 AES 加解密的正确性与效率，并打印每次测试的明文、密文与解密结果。
      - trials 次循环
      - 每次随机生成 [1..max_len] 范围内的明文长度
      - 打印每次加解密的过程
      - 最后输出累计统计
    """
    total_enc_time = 0.0
    total_dec_time = 0.0
    success_count = 0

    for i in range(trials):
        # 1) 生成随机明文
        length = random.randint(1, max_len)
        plaintext = random_string(length)

        # 2) 加密 (计时)
        start_enc = time.perf_counter()
        ciphertext = aes_encrypt(plaintext, key)
        end_enc = time.perf_counter()

        # 3) 解密 (计时)
        start_dec = time.perf_counter()
        decrypted_text = aes_decrypt(ciphertext, key)
        end_dec = time.perf_counter()

        # 4) 打印过程
        print(f"===== 第 {i+1} 次测试 =====")
        print(f"明文（length={length}）：{plaintext}")
        print(f"密文 (hex)：{ciphertext.hex()}")
        print(f"解密后：{decrypted_text}")

        # 5) 累计时间
        enc_time = end_enc - start_enc
        dec_time = end_dec - start_dec
        total_enc_time += enc_time
        total_dec_time += dec_time

        # 6) 验证正确性
        if decrypted_text == plaintext:
            success_count += 1
            print(">>> 解密结果和原文一致\n")
        else:
            print(">>> [X] 不匹配！\n")
            # 如果希望出错后就中断，可以加 break
            # break

    # ========== 输出统计结果 ==========
    print("========== 测试结束 ==========")
    print(f"总共测试次数: {trials}")
    print(f"成功次数: {success_count}")
    print(f"加密平均耗时: {total_enc_time / trials * 1000:.4f} ms/次")
    print(f"解密平均耗时: {total_dec_time / trials * 1000:.4f} ms/次")

if __name__ == "__main__":
    # 示例：16 字节主密钥 (AES-128)
    key_hex_str = "2B 7E 15 16 28 AE D2 A6 AB F7 15 88 09 CF 4F 3C"
    key = bytes.fromhex(key_hex_str.replace(" ", ""))

    # 执行测试，示例：1000 次，最大明文长度1024
    # 从命令行获取测试参数
    if len(sys.argv) < 3:
        print("错误：缺少参数！")
        print("用法: python rsa_test.py [测试次数] [最大明文长度]")
        sys.exit(1)

    # 读取测试次数和最大明文长度
    trials = int(sys.argv[1])
    max_len = int(sys.argv[2])
    test_aes_performance(key, trials=trials, max_len=max_len)

