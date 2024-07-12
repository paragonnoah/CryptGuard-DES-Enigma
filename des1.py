def string_to_bits(s):
    """Convert string s to a list of bits."""
    return [bin(ord(x))[2:].zfill(8) for x in s]

def bits_to_string(b):
    """Convert list of bits b to a string."""
    return ''.join([chr(int(x, 2)) for x in b])

def pad_message(s):
    """Pad the message s to a multiple of 8 bytes."""
    pad_length = 8 - (len(s) % 8)
    return s + chr(pad_length) * pad_length

def unpad_message(s):
    """Remove padding from the message s."""
    pad_length = ord(s[-1])
    return s[:-pad_length]

def permute_key(key, pc1_table):
    """Permute the key according to the PC1 table."""
    return [key[x - 1] for x in pc1_table]

def generate_subkeys(key, shifts, pc1_table, pc2_table):
    """Generate 16 subkeys based on the given key."""
    print("Key length:", len(key))
    print("PC1 table length:", len(pc1_table))  # Add this line for debugging
    key = permute_key(key, pc1_table)
    left_half = key[:28]
    right_half = key[28:]
    subkeys = []
    for shift in shifts:
        left_half = left_half[shift:] + left_half[:shift]
        right_half = right_half[shift:] + right_half[:shift]
        subkey = permute_key(left_half + right_half, pc2_table)
        subkeys.append(subkey)
    return subkeys


def apply_ip(data, ip_table):
    """Apply the Initial Permutation (IP) to the data."""
    return [data[x - 1] for x in ip_table]

def apply_fp(data, fp_table):
    """Apply the Final Permutation (FP) to the data."""
    return [data[x - 1] for x in fp_table]

def xor_bits(b1, b2):
    """Perform bitwise XOR operation on b1 and b2."""
    return [str(int(x) ^ int(y)) for x, y in zip(b1, b2)]

def apply_sbox(bits, sbox):
    """Apply the S-box substitution to the bits."""
    row = int(bits[0] + bits[5], 2)
    col = int(''.join(bits[1:5]), 2)
    val = sbox[row][col]
    return bin(val)[2:].zfill(4)

def feistel_function(bits, subkey, expansion_table, sboxes, p_table):
    """Perform the Feistel function."""
    bits = [bits[x - 1] for x in expansion_table]
    bits = xor_bits(bits, subkey)
    chunks = [bits[i:i+6] for i in range(0, len(bits), 6)]
    sbox_output = [apply_sbox(chunk, sbox) for chunk, sbox in zip(chunks, sboxes)]
    bits = ''.join(sbox_output)
    bits = [bits[x - 1] for x in p_table]
    return bits

def des_encrypt_block(block, subkeys, ip_table, expansion_table, sboxes, p_table, fp_table):
    """Encrypt one block using DES."""
    block = apply_ip(block, ip_table)
    left_half, right_half = block[:32], block[32:]
    for subkey in subkeys:
        new_right_half = feistel_function(right_half, subkey, expansion_table, sboxes, p_table)
        new_right_half = xor_bits(left_half, new_right_half)
        left_half = right_half
        right_half = new_right_half
    block = apply_fp(right_half + left_half, fp_table)
    return block

def des_encrypt(plaintext, key):
    """Encrypt plaintext using DES."""
    pc1_table = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18,
                 10, 2, 59, 51, 43, 35, 27, 19, 11, 3, 60, 52, 44, 36,
                 63, 55, 47, 39, 31, 23, 15, 7, 62, 54, 46, 38, 30, 22,
                 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 28, 20, 12, 4]
    pc2_table = [14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10, 23, 19,
                  12, 4, 26, 8, 16, 7, 27, 20, 13, 2, 41, 52, 31, 37,
                  47, 55, 30, 40, 51, 45, 33, 48, 44, 49, 39, 56, 34,
                  53, 46, 42, 50, 36, 29, 32]
    ip_table = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4,
                62, 54, 46, 38, 30, 22, 14, 6, 64, 56, 48, 40, 32, 24, 16, 8,
                57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3,
                61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7]
    expansion_table = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11,
                        12, 13, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21,
                        20, 21, 22, 23, 24, 25, 24, 25, 26, 27, 28, 29, 28, 29,
                        30, 31, 32, 1]
    sboxes = [
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]
    p_table = [16, 7, 20, 21, 29, 12, 28, 17,
                1, 15, 23, 26, 5, 18, 31, 10,
                2, 8, 24, 14, 32, 27, 3, 9,
                19, 13, 30, 6, 22, 11, 4, 25]
    fp_table = [40, 8, 48, 16, 56, 24, 64, 32,
                39, 7, 47, 15, 55, 23, 63, 31,
                38, 6, 46, 14, 54, 22, 62, 30,
                37, 5, 45, 13, 53, 21, 61, 29,
                36, 4, 44, 12, 52, 20, 60, 28,
                35, 3, 43, 11, 51, 19, 59, 27,
                34, 2, 42, 10, 50, 18, 58, 26,
                33, 1, 41, 9, 49, 17, 57, 25]
    shifts = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
    
    key_bits = string_to_bits(key)
    plaintext = pad_message(plaintext)
    plaintext_blocks = [plaintext[i:i+8] for i in range(0, len(plaintext), 8)]
    
    subkeys = generate_subkeys(key_bits, shifts, pc1_table, pc2_table)
    encrypted_blocks = []
    for block in plaintext_blocks:
        block_bits = string_to_bits(block)
        encrypted_block = des_encrypt_block(block_bits, subkeys, ip_table, expansion_table, sboxes, p_table, fp_table)
        encrypted_blocks.append(encrypted_block)
    
    encrypted_text = ''.join([bits_to_string(block) for block in encrypted_blocks])
    return encrypted_text

def main():
    user_input = input("Enter the encryption key: ")
    key = user_input.strip()
    with open('DES-test2024.txt', 'r') as f:
        plaintext = f.read()
    encrypted_text = des_encrypt(plaintext, key)
    with open('encrypted.txt', 'w') as f:
        f.write(encrypted_text)
    print("Encryption completed. Check encrypted.txt for the result.")

if __name__ == "__main__":
    main()
