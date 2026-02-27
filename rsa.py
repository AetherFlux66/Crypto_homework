import random
import string
import sys
import time

def is_probable_prime(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin 素性检测的实现（不依赖第三方库）。
    参数：
      - n: 待检测的正整数
      - k: 测试轮数，越大越精确（一般 40 足够课业或小型场景）
    返回：
      - True 表示 n 很可能是素数
      - False 表示 n 一定是合数
    """

    # 1. 排除小数和特殊情况
    if n < 2:
        return False
    # 如果是小素数，直接判断
    small_primes = [2, 3, 5, 7, 11, 13, 17, 19, 23, 29]
    if n in small_primes:
        return True
    # 如果能被小素数整除，返回 False
    for p in small_primes:
        if n % p == 0 and n != p:
            return False

    # 2. 将 n-1 写成 d*2^s 形式，找出 d、s
    #    (n - 1) = d << s
    d = n - 1
    s = 0
    while (d & 1) == 0:  # 当 d 是偶数
        d >>= 1
        s += 1

    # 3. Miller-Rabin 测试 k 轮
    for _ in range(k):
        # 在 [2, n-2] 范围随机选 a
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)  # 计算 a^d (mod n)
        if x == 1 or x == n - 1:
            # 这一轮可能是“伪证”，继续下一轮
            continue

        # 连续做 s-1 次平方
        for _ in range(s - 1):
            x = (x * x) % n
            if x == n - 1:
                # 依旧可能是“伪证”，继续下一轮
                break
        else:
            # 如果没有 break，说明这一轮一定判定 n 是合数
            return False
    # 如果 k 轮都没判定为合数，则“很可能是素数”
    return True


def generate_prime(bits: int = 1024) -> int:
    """
    生成一个指定比特长度的“大素数”。
    使用 Miller-Rabin 做随机测试，直到通过。
    参数：
      - bits: 所需素数的比特长度 (>= 2^bits ~ 多少)
    返回：
      - 生成的一个“高概率大素数” (int)
    """
    assert bits >= 2, "比特长度至少要 >= 2"

    while True:
        # 1) 先随机生成一个 >= 2^(bits-1) 并 < 2^bits 的奇数
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))  # 确保最高位是 1，使得数值 >= 2^(bits-1)
        candidate |= 1                 # 确保最低位是 1，使其成为奇数

        # 2) 判断它是否通过 Miller-Rabin
        if is_probable_prime(candidate, k=40):
            return candidate

def gcd(a: int, b: int) -> int:
    """计算最大公约数 (Euclidean Algorithm)"""
    while b != 0:
        a, b = b, a % b
    return a

def extended_gcd(a: int, b: int):
    """
    扩展欧几里得算法：
    返回 (g, x, y) 使得 a*x + b*y = g = gcd(a,b)
    """
    if b == 0:
        return (a, 1, 0)
    else:
        g, x1, y1 = extended_gcd(b, a % b)
        x = y1
        y = x1 - (a // b) * y1
        return (g, x, y)

def mod_inverse(a: int, m: int) -> int:
    """
    计算 a 在模 m 下的乘法逆元：a * x ≡ 1 (mod m)
    如果 gcd(a, m) != 1，则逆元不存在。
    """
    g, x, _ = extended_gcd(a, m)
    if g != 1:
        raise ValueError(f"{a} 和 {m} 不互质，无法求逆元")
    else:
        return x % m

def generate_rsa_keypair(bits=1024):
    """
    生成 RSA 公钥与私钥 (仅演示简化版):
      - bits: 指定生成的 n 大约是多大的比特数。
    返回 (e, d, n, p, q)，其中:
      - (e,n) 即公钥
      - (d,n) 即私钥
      - 这里把 p,q 返回只是为了演示/检查，实际应用中 p,q 必须保密
    """
    # 1) 生成两个大素数 p, q
    p = generate_prime(bits // 2)  # p,q 分别占 bits/2 位，简单做法
    q = generate_prime(bits // 2)
    while q == p:
        # 确保 p,q 不一样
        q = generate_prime(bits // 2)

    # 2) 计算 n = p*q
    n = p * q

    # 3) 计算 φ(n) = (p-1)*(q-1)
    phi_n = (p - 1) * (q - 1)

    # 4) 选择 e，要求 gcd(e, phi_n)=1
    #    最常用 e=65537  (十进制)
    e = 65537
    # 如果想随机选 e，也可以这样做，但要注意检验与 phi_n 的互质
    # import random
    # while True:
    #     e = random.randint(2, phi_n-1)
    #     if gcd(e, phi_n) == 1:
    #         break

    # 5) 计算 d，使 e*d ≡ 1 (mod φ(n))
    d = mod_inverse(e, phi_n)

    # 6) 返回 (e, d, n, p, q)
    return (e, d, n, p, q)

def rsa_encrypt(plaintext: bytes, e: int, n: int) -> list[int]:
    """
    分块加密：把明文 bytes 分割，然后逐块用 (m^e mod n) 处理。
    - plaintext: 待加密的字节串
    - e, n: 公钥
    - 返回: 若干整型(每块的加密结果)，存储在列表中
    """
    # 计算 n 的字节长度
    n_bytes_len = (n.bit_length() + 7) // 8
    # 这里不做填充，仅仅是裸 RSA，所以实际可用空间要小1字节，以防 m >= n
    # 当然这并不是安全的做法，只是演示“分块思路”。
    block_size = n_bytes_len - 1

    chunks = []
    # 每次取 block_size 字节
    for i in range(0, len(plaintext), block_size):
        block = plaintext[i : i + block_size]
        # 转成整数
        m = int.from_bytes(block, 'big')
        # 加密
        c = pow(m, e, n)
        chunks.append(c)
    return chunks


def rsa_decrypt(chunks: list[int], d: int, n: int) -> bytes:
    """
    与 rsa_encrypt 对应的分块解密：
    - chunks: 加密后的一串整数列表
    - d, n: 私钥
    - 返回解密得到的 bytes (未去填充)
    """
    n_bytes_len = (n.bit_length() + 7) // 8
    # 解块
    plaintext_bytes = bytearray()
    for c in chunks:
        # 解密 => m
        m = pow(c, d, n)
        # 转回 bytes，可能补齐到 n_bytes_len
        block = m.to_bytes(n_bytes_len, 'big')
        # 去掉前导 0
        block = block.lstrip(b'\x00')
        plaintext_bytes.extend(block)
    return bytes(plaintext_bytes)

def random_string(length: int) -> str:
    """
    生成指定长度的随机字符串，包含大小写字母和数字。
    """
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))


# RSA 测试函数
def test_rsa_performance(trials=10, max_len=64):
    """
    测试 RSA 加密解密的正确性和效率，并打印测试结果。
    - trials: 测试次数
    - max_len: 随机明文最大长度
    """
    total_enc_time = 0.0
    total_dec_time = 0.0
    success_count = 0
    results = []

    for i in range(trials):
        # 1) 生成随机明文
        length = random.randint(1, max_len)
        plaintext = random_string(length)
        plaintext_bytes = plaintext.encode('utf-8')

        # 2) 加密
        start_enc = time.perf_counter()
        ciphertext = rsa_encrypt(plaintext_bytes, e, n)
        end_enc = time.perf_counter()

        # 3) 解密
        start_dec = time.perf_counter()
        decrypted_bytes = rsa_decrypt(ciphertext, d, n)
        end_dec = time.perf_counter()

        # 4) 结果转换
        decrypted_text = decrypted_bytes.decode('utf-8', errors='ignore')

        # 5) 统计时间
        enc_time = end_enc - start_enc
        dec_time = end_dec - start_dec
        total_enc_time += enc_time
        total_dec_time += dec_time

        # 6) 判断正确性
        success = decrypted_text == plaintext
        if success:
            success_count += 1

        # 7) 记录测试数据
        results.append({
            "Test #": i + 1,
            "Plaintext": plaintext,
            "Ciphertext (Hex, Partial)": str(ciphertext[0])[:20] + "..." if ciphertext else "ERROR",
            "Decrypted Text": decrypted_text,
            "Encryption Time (ms)": f"{enc_time * 1000:.4f}",
            "Decryption Time (ms)": f"{dec_time * 1000:.4f}",
            "Success": success
        })

        # 8) 打印过程
        print(f"===== 第 {i + 1} 次测试 =====")
        print(f"明文（length={length}）：{plaintext}")
        print(f"密文 (Hex 部分)：{str(ciphertext[0])[:20]}...")
        print(f"解密后：{decrypted_text}")
        print(">>> 解密成功" if success else ">>> [X] 解密失败！", "\n")

    # 9) 输出统计结果
    print("========== 测试结束 ==========")
    print(f"总共测试次数: {trials}")
    print(f"成功次数: {success_count}")
    print(f"加密平均耗时: {total_enc_time / trials * 1000:.4f} ms/次")
    print(f"解密平均耗时: {total_dec_time / trials * 1000:.4f} ms/次")




# =========== 测试演示 ===========
if __name__ == "__main__":

    # 从命令行获取测试参数
    if len(sys.argv) < 3:
        print("错误：缺少参数！")
        print("用法: python rsa_test.py [测试次数] [最大明文长度]")
        sys.exit(1)

    # 读取测试次数和最大明文长度
    trials = int(sys.argv[1])
    max_len = int(sys.argv[2])

    # 生成 RSA 密钥
    e, d, n, p, q = generate_rsa_keypair(bits=1024)
    print("生成RSA密钥对：")
    print("p =", p)
    print("q =", q)
    print("n =", n)
    print("e =", e)
    print("d =", d)

    # 执行测试
    test_rsa_performance(trials=trials, max_len=max_len)