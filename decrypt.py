from string import ascii_letters, digits, punctuation

ALPHABET = bytes(ascii_letters + digits + punctuation, encoding="utf-8")
ALPHABET_SZ = len(ALPHABET)
BLOCK_SZ = 16


def split_ciphertext_in_blocks(ciphertext: bytes) -> list[bytes]:
    ciphertext_sz = len(ciphertext)
    assert ciphertext_sz % BLOCK_SZ == 0
    return [ciphertext[i: i + BLOCK_SZ] for i in range(0, ciphertext_sz, 16)]


def get_ind(char: int) -> int:
    return ALPHABET.find(char)


def unrotate_block(block: bytes, key: int) -> bytes:
    new_block = [0 for _ in range(BLOCK_SZ)]

    for i in range(BLOCK_SZ):
        ind = get_ind(block[i])

        if ind == -1:
            new_block[i] = block[i]
            continue

        ind -= key
        if ind < 0:
            ind += ALPHABET_SZ

        new_block[i] = ALPHABET[ind]

    return new_block


def unshift_block(block: bytes, key: int) -> bytes:
    keymod = key % BLOCK_SZ
    unshifted_block = block[-keymod:] + block[:-keymod]
    return unshifted_block


def merge_blocks(block1: bytes, block2: bytes) -> bytes:
    assert len(block1) == BLOCK_SZ
    assert len(block2) == BLOCK_SZ

    res = [0 for _ in range(BLOCK_SZ)]
    for i in range(BLOCK_SZ):
        res[i] = block1[i] ^ block2[i]
    return res


def check_is_block_valid(block: bytes) -> bool:
    return all([chr(char) in ALPHABET for char in block])


def prettify(block: bytes) -> str:
    return "".join([chr(lt) for lt in block])


def decrypt_block(prev: bytes, block: bytes, key: int) -> bytes:
    unshifted = unshift_block(block, key)
    unrotated = unrotate_block(unshifted, key)
    unmerged = merge_blocks(prev, unrotated)
    return unmerged


def decrypt_text(ciphertext: bytes, iv: bytes, key: int) -> str:
    ciphertext_blocks = split_ciphertext_in_blocks(ciphertext)
    blocks_cnt = len(ciphertext_blocks)
    plaintext_blocks = [prettify(decrypt_block(iv, ciphertext_blocks[0], key))]
    for i in range(1, blocks_cnt):
        plaintext_blocks.append(
            prettify(decrypt_block(
                ciphertext_blocks[i - 1], ciphertext_blocks[i], key))
        )
    return "".join(plaintext_blocks)


if __name__ == "__main__":

    ciphertext = b'.r;oms\x02\x07\x15\x1e\x15W8):+\tVQ94\neZ\x03AsIjsH\x14\x1d@iq\'<2"B\x16Mx,\x03.\x0f:1`K;V:uu\x1f\x13Dbz\x11h#o\x1dV!\r|9\'\x1a\x19\x10xt.\x10\x04SHN\x1cvb7K\x082UG-F\x11U)%IF}=l\x02OR_Kg(;Te5(\tV]&\t!\x1e/,|\\:e~e%R\x04\x1blalWy7wWg9*\x0b\x11\x1b\x17\x05|C|\x05\x0fY:\x114\x1aKTVOwFmp\\e\x11\'3awc\x049{[G<b\x12<\x04\x11$RESE={\x0co\x19\x0f\'/\x1c.F"JC8-pe)7\x1em1At0YG\x0e%PiS-U\x06\x00R!A\x087n\x1dgL=RA\x1f\x0c~"H6BbQB[\x15Yb'
    key = 13
    iv = b"0123456789ABCDEF"

    print(decrypt_text(ciphertext, iv, key))
