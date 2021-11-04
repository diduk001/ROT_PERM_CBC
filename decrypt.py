ALPHABET_SZ = 256
BLOCK_SZ = 16


def split_ciphertext_in_blocks(ciphertext: bytes) -> list[bytes]:
    ciphertext_sz = len(ciphertext)
    assert ciphertext_sz % BLOCK_SZ == 0

    return [ciphertext[i : i + BLOCK_SZ] for i in range(0, ciphertext_sz, 16)]


def unrotate_block(block: bytes, key: int) -> bytes:
    new_block = [0 for _ in range(BLOCK_SZ)]

    for i in range(BLOCK_SZ):
        ind = block[i]
        ind -= key
        if ind < 0:
            ind += ALPHABET_SZ
        new_block[i] = ind

    return bytes(new_block)


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
    return bytes(res)


def decrypt_block(prev: bytes, block: bytes, key: int) -> bytes:
    unshifted = unshift_block(block, key)
    unrotated = unrotate_block(unshifted, key)
    unmerged = merge_blocks(prev, unrotated)
    return unmerged


def unpad(text: bytes) -> bytes:
    return text[: -text[-1]]


def decrypt_text(ciphertext: bytes, iv: bytes, key: int) -> bytes:
    ciphertext_blocks = split_ciphertext_in_blocks(ciphertext)
    blocks_cnt = len(ciphertext_blocks)
    plaintext_blocks = [decrypt_block(iv, ciphertext_blocks[0], key)]
    for i in range(1, blocks_cnt):
        prev_block = ciphertext_blocks[i - 1]
        cur_block = ciphertext_blocks[i]

        new_block = decrypt_block(prev_block, cur_block, key)
        plaintext_blocks.append(new_block)

    joined = b"".join(plaintext_blocks)
    return unpad(joined)


if __name__ == "__main__":

    ciphertext = b'.r1o\x8bs\x0f\x14"+"WcB0DoP8d_\ri\xb8\x10p\x82N[^\x82\\=\xf05\x0fBY\x1a?u\'\xa5\x85\x16\xff3K\xec_xe\xa1"j\x1a\x1aD\x1bS\x1b\x92\xf9r\xbf\x97\x14\xacC""\xdaTW\x83\x8c=|Cv\x198 \xea\xf1m\xd2Ddc\xc0HF\xb0\xfca\xe2\x9cNx%a\x8f\x9d&\xffC\x0e \xb962\xa6Og\x90\xc9/*^"\xf7\xfc\x13\x957\x87U$\xf3@\xd0|c\xb0\xcaT\x17?T\x90\x95\x83\xf4\xc2\xef\xa5]\xa3?\xfd"$\x9d\xb0GDXI\x02\x85-~\xbf\x94\xd1L\xd3X\xe0\x0f\x83\xdf\xf1\x83\x84\x8f\xf3\xb1\xb2Yk\xd9\xf1\xc1<\xc7F\x99<\xed\xcb)\x9b\xaf\xed\xa2\x9e\xd3>\x1b\x06\xbf\xadf\xc14\xf8\xbf!\xa9f\x00\xd7\xac\x8f\xf6\xc8d\x85{\xac\xe7\x14\xcf\x91\x8a\xe7d\xd9\x17|\xb4\xd6\xf8\xe3\xae\x17\xb2\'\x1d\xc2-\xb7\x0c\x0b\xd4C\xc3\x87&\xa7\xde\x0c\xf1\xb6'
    key = 13
    iv = b"0123456789ABCDEF"

    print(decrypt_text(ciphertext, iv, key))
