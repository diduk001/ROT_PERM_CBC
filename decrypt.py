from string import ascii_letters, digits, punctuation

ALPHABET = bytes(ascii_letters + digits + punctuation, encoding="utf-8")
ALPHABET_SZ = len(ALPHABET)
BLOCK_SZ = 16

ciphertext = b'DECFmmDECllEDFmm\x05`.\x08\n\x00\x05`.\x0b\x06\x00_ \n\x07oSUW:zWS1S:yTVP\x1c\x1a\x1fh]\x10\x17\x1bH-\x14\x11l\x1cL{\x16\x03,7"f;\x1256"\x04o94_2J\x1cCNiKn<LgMHnS:I\x10K\x05\x065\x00\r\\\x07.\x7f\x0f<\x01\x07^PX\x11h\x08SQL10\x1fRo$Y\x7fu\x16}\x13\x1b5;T\x10\x12\x0el\x7fe\x11^[4\x1d*6%e!IL\x18h3Z_\'\x19\x1cr\x19K4vHt@A\n\x0f#;kiL>75%#\tK-\x0b+\x02\rRY0\x11\x1a=\x0flHLwiW\x08AUuN'


def split_ciphertext_in_blocks(ciphertext: bytes) -> list[bytes]:
    ciphertext_sz = len(ciphertext)
    assert ciphertext_sz % BLOCK_SZ == 0
    return [ciphertext[i : i + BLOCK_SZ] for i in range(0, ciphertext_sz, 16)]


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
            prettify(decrypt_block(ciphertext_blocks[i - 1], ciphertext_blocks[i], key))
        )
    return "".join(plaintext_blocks)


if __name__ == "__main__":
    print(decrypt_text(ciphertext, b"12" * 8, 13))
