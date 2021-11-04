# rot + shift + cbc

from string import ascii_letters, digits, punctuation

ALPHABET = bytes(ascii_letters + digits + punctuation, encoding="utf-8")
ALPHABET_SZ = len(ALPHABET)
BLOCK_SZ = 16


def get_ind(char: int) -> int:
    return ALPHABET.find(char)


def rotate_char(char: int, key: int) -> int:
    ind = get_ind(char)

    if ind == -1:
        return char

    new_ind = (ind + key) % ALPHABET_SZ
    new_char = ALPHABET[new_ind]

    return new_char


def shift_block(block: bytes, key: int) -> bytes:
    keymod = key % BLOCK_SZ

    shifted_block = block[keymod:] + block[:keymod]

    return shifted_block


def encrypt_one_block(block: bytes, key: int) -> bytes:
    assert len(block) == BLOCK_SZ

    rotated_block = [rotate_char(char, key) for char in block]
    encrypted_block = shift_block(rotated_block, key)

    return encrypted_block


# strange pkcs 7 version
def pad(text: str) -> str:
    remainds = BLOCK_SZ - (len(text) % BLOCK_SZ)
    ind_remainds = remainds % ALPHABET_SZ
    return text + text[ind_remainds] * remainds


def split_text_in_blocks(text: str) -> list[bytes]:
    padded_text = bytes(pad(text), encoding="utf-8")
    text_sz = len(padded_text)
    return [padded_text[i : i + BLOCK_SZ] for i in range(0, text_sz, 16)]


def merge_blocks(block1: bytes, block2: bytes) -> bytes:
    assert len(block1) == BLOCK_SZ
    assert len(block2) == BLOCK_SZ

    res = [0 for _ in range(BLOCK_SZ)]
    for i in range(BLOCK_SZ):
        res[i] = block1[i] ^ block2[i]
    return res


def prettify(encrypted: list[list[str]]) -> str:
    return "".join(["".join([chr(char) for char in block]) for block in encrypted])


def encrypt_text(text: str, key: int, iv: bytes) -> bytes:
    assert isinstance(iv, bytes) and len(iv) == BLOCK_SZ

    splitted_text = split_text_in_blocks(text)
    blocks_cnt = len(splitted_text)

    ciphertext_blocks = [[] for __ in range(blocks_cnt)]

    first_block_merged = merge_blocks(iv, splitted_text[0])
    ciphertext_blocks[0] = encrypt_one_block(first_block_merged, key)

    for i in range(1, blocks_cnt):
        cur_block_merged = merge_blocks(ciphertext_blocks[i - 1], splitted_text[i])
        ciphertext_blocks[i] = bytes(encrypt_one_block(cur_block_merged, key))

    ciphertext = list()
    for block in ciphertext_blocks:
        ciphertext.extend(block)

    return bytes(ciphertext)


if __name__ == "__main__":
    text = """ROT13 ("rotate by 13 places", sometimes hyphenated ROT-13) is a simple letter substitution cipher that replaces a letter with the 13th letter after it in the alphabet. ROT13 is a special case of the Caesar cipher which was developed in ancient Rome."""
    key = 13
    iv = b"0123456789ABCDEF"
    print(encrypt_text(text, key, iv))
