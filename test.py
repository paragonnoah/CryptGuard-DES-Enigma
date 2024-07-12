def generate_key(user_input):
    """
    Generate a 64-bit DES key from user input.
    """
    key = user_input.encode()[:8]  # Ensure key is 8 bytes long
    return key



# Initial and final permutation tables
initial_permutation = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]

final_permutation = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]



# Permutation functions
def permute(data, table):
    permuted_data = 0
    for i, bit_position in enumerate(table):
        bit = (data >> (64 - bit_position)) & 0x01
        permuted_data |= bit << (63 - i)
    return permuted_data

# Feistel function
def feistel_function(data, subkey):
    """
    Feistel function used in DES encryption.
    """
    # Expansion permutation
    expansion_permutation = [
    32,  1,  2,  3,  4,  5,  4,  5,
     6,  7,  8,  9,  8,  9, 10, 11,
    12, 13, 14, 15, 16, 17, 16, 17,
    18, 19, 20, 21, 20, 21, 22, 23,
    24, 25, 26, 27, 26, 27, 28, 29,
    30, 31, 32,  1
]

    expanded_data = 0
    for i, bit_position in enumerate(expansion_permutation):
        bit = (data >> (32 - bit_position)) & 0x01
        expanded_data |= bit << (47 - i)

    # XOR with subkey
    xor_result = expanded_data ^ subkey

    # S-box substitution
    s_boxes = [
        # S-box 1
        [
            [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
            [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
            [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
            [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
        ],
        # S-box 2
        [
            [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
            [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
            [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
            [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
        ],
        # S-box 3
        [
            [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
            [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
            [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
            [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
        ],
        # S-box 4
        [
            [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
            [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
            [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
            [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
        ],
        # S-box 5
        [
            [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
            [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
            [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
            [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
        ],
        # S-box 6
        [
            [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
            [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
            [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
            [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
        ],
        # S-box 7
        [
            [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
            [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
            [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
            [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
        ],
        # S-box 8
        [
            [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
            [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
            [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
            [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
        ]
    ]

    s_box_output = 0
    for i in range(8):
        # Extract 6 bits from XOR result corresponding to S-box i
        bits = (xor_result >> (42 - 6 * i)) & 0x3F
        # Calculate row and column indices for the S-box
        row = ((bits & 0x20) >> 4) | (bits & 0x01)
        col = (bits >> 1) & 0x0F
        # Get the value from the S-box
        s_box_output |= s_boxes[i][row][col] << (28 - 4 * i)

    # Straight permutation
    straight_permutation = [
        16, 7, 20, 21,
        29, 12, 28, 17,
        1, 15, 23, 26,
        5, 18, 31, 10,
        2, 8, 24, 14,
        32, 27, 3, 9,
         19, 13, 30, 6,
        22, 11, 4, 25
    ]

    feistel_output = 0
    for i, bit_position in enumerate(straight_permutation):
        bit = (s_box_output >> (32 - bit_position)) & 0x01
        feistel_output |= bit << (31 - i)

    return feistel_output

# Expansion permutation function
def expansion_permutation(data):
    """
    Performs the expansion permutation on the given data.
    """
    expansion_permutation_table = [
        32, 1, 2, 3, 4, 5,
        4, 5, 6, 7, 8, 9,
        8, 9, 10, 11, 12, 13,
        12, 13, 14, 15, 16, 17,
        16, 17, 18, 19, 20, 21,
        20, 21, 22, 23, 24, 25,
        24, 25, 26, 27, 28, 29,
        28, 29, 30, 31, 32, 1
    ]

    expanded_data = 0
    for i, bit_position in enumerate(expansion_permutation_table):
        bit = (data >> (32 - bit_position)) & 0x01
        expanded_data |= bit << (47 - i)

    return expanded_data

# DES round function
def des_round(data, subkey):
    # Initial permutation
    data = permute(data, initial_permutation)
    
    # Split data into left and right halves
    left_half = data >> 32
    right_half = data & 0xFFFFFFFF
    
    # Perform expansion permutation on the right half
    expanded_right_half = expansion_permutation(right_half)
    
    # Convert subkey to integer
    subkey_int = int.from_bytes(subkey, byteorder='big')
    
    # XOR the expanded right half with the subkey
    xor_result = expanded_right_half ^ subkey_int
    
    # Apply the Feistel function
    feistel_output = feistel_function(xor_result, subkey_int)
    
    # XOR the feistel output with the left half
    new_right_half = left_half ^ feistel_output
    
    # Combine the new right half with the original right half
    new_data = (right_half << 32) | new_right_half
    
    # Final permutation
    encrypted_data = permute(new_data, final_permutation)
    
    return encrypted_data

# DES encryption function
def encrypt_block(block, key):
    # Initial permutation
    block = permute(block, initial_permutation)
    # Perform DES rounds
    for i in range(16):
        block = des_round(block, key)
    # Final permutation
    block = permute(block, final_permutation)
    return block



def encrypt(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        plaintext = f.read()
    # Pad plaintext if necessary
    padding_length = 8 - len(plaintext) % 8
    plaintext += bytes([padding_length] * padding_length)

    ciphertext = b''
    for i in range(0, len(plaintext), 8):
        block = int.from_bytes(plaintext[i:i+8], 'big')
        encrypted_block = encrypt_block(block, key)
        ciphertext += encrypted_block.to_bytes(8, 'big')
    
    with open(output_file, 'wb') as f:
        f.write(ciphertext)

# DES decryption round function
def des_decrypt_round(data, subkey):
    # Initial permutation
    data = permute(data, initial_permutation)
    
    # Split data into left and right halves
    left_half = data >> 32
    right_half = data & 0xFFFFFFFF
    
    # Perform expansion permutation on the right half
    expanded_right_half = expansion_permutation(right_half)
    
    # Convert subkey to integer
    subkey_int = int.from_bytes(subkey, byteorder='big')
    
    # XOR the expanded right half with the subkey
    xor_result = expanded_right_half ^ subkey_int
    
    # Apply the Feistel function
    feistel_output = feistel_function(xor_result, subkey_int)
    
    # XOR the feistel output with the left half
    new_right_half = left_half ^ feistel_output
    
    # Combine the new right half with the original right half
    new_data = (right_half << 32) | new_right_half
    
    # Final permutation
    decrypted_data = permute(new_data, final_permutation)
    
    return decrypted_data

def decrypt_block(block, key):
    # Initial permutation
    block = permute(block, initial_permutation)
    # Perform DES rounds in reverse order
    for i in range(16):
        block = des_decrypt_round(block, key)
    # Final permutation
    block = permute(block, final_permutation)
    return block

def decrypt(input_file, output_file, key):
    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    plaintext = b''
    for i in range(0, len(ciphertext), 8):
        block = int.from_bytes(ciphertext[i:i+8], 'big')
        decrypted_block = decrypt_block(block, key)  # Remove key reversal
        plaintext += decrypted_block.to_bytes(8, 'big')

    # Remove padding
    padding_length = plaintext[-1]
    plaintext = plaintext[:-padding_length]

    with open(output_file, 'wb') as f:
        f.write(plaintext)


def main():
    user_input = input("Enter the encryption key: ")
    key = generate_key(user_input)

    # Encrypt DES-test2024.txt and save as encrypted.txt
    encrypt('DES-test2024.txt', 'encrypted.txt', key)
    # Decrypt encrypted.txt and save as decrypted.txt
    decrypt('encrypted.txt', 'decrypted.txt', key)

    print("Encryption and Decryption completed. Check encrypted.txt and decrypted.txt.")

if __name__ == "__main__":
    main()

