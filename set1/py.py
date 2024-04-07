from collections import Counter

if __name__ == "__main__":
    with open('ciphertexts_C4.txt') as f:
        inps = f.readlines()
    for inp in inps:
        inp = inp.strip()
        tmp = inp
        inp = bytes.fromhex(inp)
        c = Counter(inp)
        key = max(c, key=c.get) ^ ord(' ')
        out = ''.join(map(lambda x: chr(x ^ key), inp)).strip()
        if out.isprintable():
            print(f"Ciphertext: {tmp}")
            # print(f"Key: {chr(key ^ 32)}")
            print(out)