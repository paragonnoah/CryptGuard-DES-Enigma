INITIAL_PERMUTATION = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    63, 55, 47, 39, 31, 23, 15, 7,
    59, 51, 43, 35, 27, 19, 11, 3,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    30, 38, 22, 14, 6,  0, 54, 46,
    29, 37, 21, 13,  5, 61, 53, 45
]

EXPANSION_PERMUTATION = [
    32,  1,  2,  3,  4,  5,  4,  5,
     6,  7,  8,  9,  8,  9, 10, 11,
    12, 13, 14, 15, 16, 17, 16, 17,
    18, 19, 20, 21, 20, 21, 22, 23,
    24, 25, 26, 27, 26, 27, 28, 29,
    30, 31, 32,  1
]

S_BOXES = [
    # S1
    [[14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
     [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
     [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
     [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]],

    # S2
    [[15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
     [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
     [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
     [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]],

    # S3
    [[10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
     [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
     [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
     [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]],

    # S4
    [[7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
     [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
     [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
     [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]],

    # S5
    [[2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
     [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
     [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
     [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]],

    # S6
    [[12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
     [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
     [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
     [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]],

    # S7
    [[4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
     [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
     [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]]
]


P_PERMUTATION = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1,  5, 23, 26,
     2, 14, 19, 22,
     9,  8, 24, 25,
    11,  3, 30,  4,
     10, 27,  6, 15,
     13,  6,  8, 11
]

PC1 = [
    57, 49, 41, 33, 2
]

def permute(data, table):
    """
    Performs a permutation on a binary string (`data`) using a lookup table (`table`).

    Args:
        data (str): A binary string to be permuted.
        table (list): A list representing the permutation order.

    Returns:
        str: The permuted binary string.
    """

    if not isinstance(data, str) or not all(char in "01" for char in data):
        raise ValueError("Input data must be a binary string.")

    result = ['0'] * len(table)  # Initialize result with zeros
    for i in range(len(table)):
        result[i] = data[table[i] - 1]  # Use table index to access data bits

    return ''.join(result)


def generate_subkeys(key):
    """
    Generates the 16 subkeys for DES encryption/decryption (for educational purposes only).

    Args:
        key (str): A binary string representing the 64-bit DES key.

    Returns:
        list: A list of 16 binary strings representing the subkeys.
    """

    # Check if key is a valid 64-bit binary string
    if not isinstance(key, str) or not all(char in "01" for char in key) or len(key) != 64:
        raise ValueError("Input key must be a 64-bit binary string.")

    # Perform Permuted Choice 1 (PC1) on the key
    pc1 = [57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, ...]  # Full table (56 elements)
    C0 = permute(key, pc1)  # Left half of permuted key
    D0 = C0[28:]  # Right half of permuted key

    subkeys = []  # List to store subkeys

    # Generate 16 subkeys using left and right shifts and PC2 permutation
    for i in range(1, 17):
        # Perform left circular shifts on C0 and D0 based on the shift schedule
        shift_schedule = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]
        C0 = (C0[shift_schedule[i - 1]:] + C0[:shift_schedule[i - 1]])
        D0 = (D0[shift_schedule[i - 1]:] + D0[:shift_schedule[i - 1]])

        # Combine C0 and D0
        subkey_combined = C0 + D0

        # Perform Permuted Choice 2 (PC2) to get the final 48-bit subkey
        pc2 = [14, 16, 15, 17, 8, 13, 7, 11, 4, 1, 5, 9, 3, 12, 2, 6, ...]  # Full table (48 elements)
        subkey = permute(subkey_combined, pc2)

        subkeys.append(subkey)

    return subkeys


def xor(a, b):
  """
  Performs bitwise XOR operation on two binary strings.

  Args:
      a (str): A binary string.
      b (str): Another binary string.

  Returns:
      str: The resulting binary string after XOR operation.
  """

  # Check if both strings are binary and of equal length
  if not isinstance(a, str) or not isinstance(b, str) or not all(char in "01" for char in a + b) or len(a) != len(b):
    raise ValueError("Input strings must be binary and of equal length.")

  result = ""
  for i in range(len(a)):
    # Perform XOR using string indexing and conversion to integers
    result += str((int(a[i]) ^ int(b[i])))

  return result

def f_function(data, subkey):
    """
    Implements the f-function of DES encryption (for educational purposes only).

    Args:
        data (str): A 32-bit binary string representing the data block.
        subkey (str): A 48-bit binary string representing the subkey.

    Returns:
        str: A 32-bit binary string representing the output of the f-function.
    """

    # Check if data and subkey are valid binary strings
    if not isinstance(data, str) or not isinstance(subkey, str) or not all(char in "01" for char in data + subkey) or len(data) != 32 or len(subkey) != 48:
        raise ValueError("Input data and subkey must be binary strings of correct lengths (32 and 48 bits).")

    # Perform expansion permutation (E)
    expansion_permutation = [32, 1, 2, 3, 4, 5, 4, 5, 6, 7, 8, 9, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 16, 17, 18, 19, 20, 21, 20, 21, 22, 23, 24, 25, 26, 27, 26, 27, 28, 29, 30, 31, 32, 1]
    expanded_data = permute(data, expansion_permutation)

    # XOR expanded data with subkey
    xored_data = xor(expanded_data, subkey)

    # S-Box substitution
    s_boxes = [  # Replace with actual S-box values (avoid real-world use)
        [[], [], [], []],  # S0
        [[], [], [], []],  # S1
        # ... Define remaining S-boxes (S2 to S7)
    ]
    substituted_data = ""
    for i in range(0, 48, 6):  # Process each 6-bit chunk
        row = int(xored_data[i] + xored_data[i + 5], 2)  # Convert first and last bits to decimal for row index
        col = int(xored_data[i + 1:i + 5], 2)  # Convert middle 4 bits to decimal for column index
        substitute = bin(s_boxes[i // 6][row * 16 + col])[2:].zfill(4)  # Lookup S-box and convert to binary string
        substituted_data += substitute

    # P-permutation
    p_permutation = [16, 7, 20, 21, 29, 12, 28, 17, 1, 5, 23, 26, 2, 14, 19, 22, 9, 8, 24, 25, 11, 3, 30, 4, 10, 27, 6, 15, 13, 6]
    result = permute(substituted_data, p_permutation)

    return result


def des_round(data, subkey):
  """
  Performs a single DES round of encryption/decryption.

  Args:
      data (str): A 64-bit binary string representing the data block.
      subkey (str): A 48-bit binary string representing the subkey.

  Returns:
      str: A 64-bit binary string representing the output after the round.
  """

  # Check if data and subkey are valid binary strings
  if not isinstance(data, str) or not isinstance(subkey, str) or not all(char in "01" for char in data + subkey) or len(data) != 64 or len(subkey) != 48:
    raise ValueError("Input data and subkey must be binary strings of correct lengths (64 and 48 bits).")

  # Left half of the data block (L)
  left = data[:32]

  # Right half of the data block (R)
  right = data[32:]

  # Perform f-function on right half and XOR with left half
  f_output = f_function(right, subkey)
  new_left = xor(left, f_output)

  # Combine new left and right halves
  result = new_left + right

  return result


def encrypt(data, key):
  """
  Encrypts a binary string (`data`) using DES encryption (for educational purposes only).

  Args:
      data (str): A binary string to be encrypted (must be a multiple of 64 bits).
      key (str): A 64-bit binary string representing the DES key.

  Returns:
      str: The encrypted binary string (ciphertext).
  """

  # Check if data is a multiple of 64 bits and a valid binary string
  if not isinstance(data, str) or not all(char in "01" for char in data) or len(data) % 64 != 0:
    raise ValueError("Input data must be a binary string and a multiple of 64 bits.")

  # Check if key is a valid 64-bit binary string
  if not isinstance(key, str) or not all(char in "01" for char in key) or len(key) != 64:
    raise ValueError("Input key must be a 64-bit binary string.")

  # Initial permutation (IP)
  initial_permutation = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 63, 55, 47, 39, 31, 23, 15, 7, 59, 51, 43, 35, 27, 19, 11, 3, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 30, 38, 22, 14, 6,  0, 54, 46, 29, 37, 21, 13,  5, 61, 53, 45]
  permuted_data = permute(data, initial_permutation)

  # Generate subkeys
  subkeys = generate_subkeys(key)

  # DES rounds (16 rounds)
  left = permuted_data[:32]
  right = permuted_data[32:]
  for i in range(16):
    round_output = des_round(right, subkeys[i])
    new_left = xor(left, round_output)
    left = right
    right = new_left

  # Combine final left and right halves
  final_data = left + right

  # Final permutation (IP^-1)
  final_permutation = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 1, 42, 10, 50, 18, 58, 26, 33, 9, 41, 2, 49, 17, 57, 25]
  ciphertext = permute(final_data, final_permutation)

  return ciphertext


def decrypt(ciphertext, key):
  """
  Decrypts a binary string (`ciphertext`) using DES decryption (for educational purposes only).

  Args:
      ciphertext (str): A binary string to be decrypted (must be a multiple of 64 bits).
      key (str): A 64-bit binary string representing the DES key.

  Returns:
      str: The decrypted binary string (plaintext).
  """

  # Check if ciphertext is a multiple of 64 bits and a valid binary string
  if not isinstance(ciphertext, str) or not all(char in "01" for char in ciphertext) or len(ciphertext) % 64 != 0:
    raise ValueError("Input ciphertext must be a binary string and a multiple of 64 bits.")

  # Check if key is a valid 64-bit binary string
  if not isinstance(key, str) or not all(char in "01" for char in key) or len(key) != 64:
    raise ValueError("Input key must be a 64-bit binary string.")

  # Inverse initial permutation (IP^-1)
  inverse_initial_permutation = [40, 8, 48, 16, 56, 24, 64, 32, 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 1, 42, 10, 50, 18, 58, 26, 33, 9, 41, 2, 49, 17, 57, 25]
  permuted_data = permute(ciphertext, inverse_initial_permutation)

  # Generate subkeys (same subkeys used for encryption)
  subkeys = generate_subkeys(key)

  # DES rounds (16 rounds - used in reverse order)
  left = permuted_data[:32]
  right = permuted_data[32:]
  for i in range(15, -1, -1):  # Decryption uses subkeys in reverse order
    round_output = des_round(right, subkeys[i])
    new_left = xor(left, round_output)
    left = right
    right = new_left

  # Combine final left and right halves
  final_data = left + right

  # Final permutation (IP)
  final_permutation = [58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 63, 55, 47, 39, 31, 23, 15, 7, 59, 51, 43, 35, 27, 19, 11, 3, 64, 56, 48, 40, 32, 24, 16, 8, 57, 49, 41, 33, 25, 17, 9, 1, 30, 38, 22, 14, 6,  0, 54, 46, 29, 37, 21, 13,  5, 61, 53, 45]
  plaintext = permute(final_data, final_permutation)

  return plaintext

def main():
    # User input for key
    user_input = input("Enter the encryption key: ")
    key = user_input[:64]  # Limit key to 64 characters

    # Read the contents of the file for encryption
    with open('DES-test2024.txt', 'r') as file:
        plaintext = file.read()

    # Convert plaintext to binary using ASCII encoding
    binary_plaintext = ''.join(format(ord(char), '08b') for char in plaintext)

    # Encrypt the plaintext
    ciphertext = encrypt(binary_plaintext, key)

    # Write the encrypted text to a file
    with open('encrypted.txt', 'w') as file:
        file.write(ciphertext)

    # Decrypt the ciphertext
    decrypted_text = decrypt(ciphertext, key)

    # Convert decrypted binary string to plaintext
    decrypted_plaintext = ''.join(chr(int(decrypted_text[i:i+8], 2)) for i in range(0, len(decrypted_text), 8))

    # Write the decrypted text to a file
    with open('decrypted.txt', 'w') as file:
        file.write(decrypted_plaintext)

    print("Encryption and Decryption completed. Check encrypted.txt and decrypted.txt.")

if __name__ == "__main__":
    main()



