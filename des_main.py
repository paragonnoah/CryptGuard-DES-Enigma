#initail permutation
ip_table = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17, 9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
]
# PC1 permutation table
pc1_table = [
    57, 49, 41, 33, 25, 17, 9, 1,
    58, 50, 42, 34, 26, 18, 10, 2,
    59, 51, 43, 35, 27, 19, 11, 3,
    60, 52, 44, 36, 63, 55, 47, 39,
    31, 23, 15, 7, 62, 54, 46, 38,
    30, 22, 14, 6, 61, 53, 45, 37,
    29, 21, 13, 5, 28, 20, 12, 4
]
# Define the left shift schedule for each round
shift_schedule = [1, 1, 2, 2,
                  2, 2, 2, 2,
                  1, 2, 2, 2,
                  2, 2, 2, 1]

# PC2 permutation table
pc2_table = [
    14, 17, 11, 24, 1, 5, 3, 28,
    15, 6, 21, 10, 23, 19, 12, 4,
    26, 8, 16, 7, 27, 20, 13, 2,
    41, 52, 31, 37, 47, 55, 30, 40,
    51, 45, 33, 48, 44, 49, 39, 56,
    34, 53, 46, 42, 50, 36, 29, 32
]
#expension
e_box_table = [
    32, 1, 2, 3, 4, 5,
    4, 5, 6, 7, 8, 9,
    8, 9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32, 1
]

# S-box tables for DES
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
p_box_table = [
    16, 7, 20, 21, 29, 12, 28, 17,
    1, 15, 23, 26, 5, 18, 31, 10,
    2, 8, 24, 14, 32, 27, 3, 9,
    19, 13, 30, 6, 22, 11, 4, 25
]
ip_inverse_table = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41, 9, 49, 17, 57, 25
]

def str_to_bin(user_input):
    # Convert the string to binary
    binary_representation = ''
    
    for char in user_input:
        # Get ASCII value of the character and convert it to binary
        binary_char = format(ord(char), '08b')
        binary_representation += binary_char
    
    # Pad the binary representation to ensure it's a multiple of 64 bits
    padding_length = (64 - len(binary_representation) % 64) % 64
    binary_representation += '0' * padding_length
    
    # Print the length of the binary representation
    #print(len(binary_representation), 'bits of input string')
    
    return binary_representation

        
def binary_to_ascii(binary_str):
    ascii_str = ''.join([chr(int(binary_str[i:i+8], 2)) for i in range(0, len(binary_str), 8)])
    return ascii_str

def ascii_to_binary(ascii_str):
    binary_str = ''.join(format(ord(char), '08b') for char in ascii_str)
    return binary_str


def ip_on_binary_rep(binary_representation):
    if len(binary_representation) % 64 != 0:
        raise ValueError("Binary representation must be a multiple of 64 bits.")

    ip_result = ''
    num_blocks = len(binary_representation) // 64  # Calculate the number of 64-bit blocks
    
    for block_num in range(num_blocks):
        block_start = block_num * 64
        block_end = (block_num + 1) * 64
        block = binary_representation[block_start:block_end]
        
        ip_block = [''] * 64
        for i in range(64):
            ip_block[i] = block[ip_table[i] - 1]  # Apply the IP permutation to the block
        ip_result += ''.join(ip_block)  # Concsatenate the IP blocks
    
    return ip_result

def key_in_binary_conv(original_key):
    binary_representation_key = ''
    
    for char in original_key:
        # Convert the characters to binary and concatenate to form a 64-bit binary string
        binary_key = format(ord(char), '08b') 
        binary_representation_key += binary_key

    return binary_representation_key
 
def generate_round_keys(key):
    # Key into binary
    binary_representation_key = key_in_binary_conv(key)
    pc1_key_str = ''.join(binary_representation_key[bit - 1] for bit in pc1_table)

    # Split the 56-bit key into two 28-bit halves
    c0 = pc1_key_str[:28]
    d0 = pc1_key_str[28:]
    round_keys = []
    for round_num in range(16):
        # Perform left circular shift on C and D
        c0 = c0[shift_schedule[round_num]:] + c0[:shift_schedule[round_num]]
        d0 = d0[shift_schedule[round_num]:] + d0[:shift_schedule[round_num]]
        # Concatenate C and D
        cd_concatenated = c0 + d0

        # Apply the PC2 permutation
        round_key = ''.join(cd_concatenated[bit - 1] for bit in pc2_table)

        # Store the round key
        round_keys.append(round_key)
    return round_keys

def divide_into_sixty_fours(binary_list):
    n = len(binary_list)
    remainder = n % 64
    if remainder != 0:
        padded_list = binary_list + ['0' * (64 - remainder)]  # Pad the list to make it a multiple of 64
    else:
        padded_list = binary_list
    rows = len(padded_list) // 64
    two_d_array = []

    for i in range(rows):
        start = i * 64
        end = start + 64
        two_d_array.append(padded_list[start:end])

    return two_d_array
def encryption(input_file, output_file, key):
    # Read the content of the input file
    with open(input_file, 'r') as file:
        user_input = file.read()

    binary_rep_of_input = str_to_bin(user_input)

    # Initialize lists to store round keys
    round_keys = generate_round_keys(key)



    ip_result_str = ip_on_binary_rep(binary_rep_of_input)
   # print("Length of IP result:", len(ip_result_str))  # Debugging statement


    # The initial permutation result is divided into 2 halves
    ip_result_str1 = divide_into_sixty_fours(ip_result_str)


  #  print("Length of IP result:", len(ip_result_str1))  # Debugging statement
    concatenated_output = ''
    with open(output_file, 'w') as file:
        for ip_result1 in ip_result_str1:
        

            lpt = ip_result1[:32]
            rpt = ip_result1[32:]

            for round_num in range(16):
                # Perform expansion (32 bits to 48 bits)
                expanded_result = [rpt[i - 1] for i in e_box_table]

                # Convert the result back to a string for better visualization
                expanded_result_str = ''.join(expanded_result)

                # Round key for the current round
                round_key_str = round_keys[round_num]

                xor_result_str = ''
                for i in range(48):
                    xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))

                # Split the 48-bit string into 8 groups of 6 bits each
                six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]

                # Initialize the substituted bits string
                s_box_substituted = ''

                # Apply S-box substitution for each 6-bit group
                for i in range(8):
                    # Extract the row and column bits
                    row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
                    col_bits = int(six_bit_groups[i][1:-1], 2)

                    # Lookup the S-box value
                    s_box_value = s_boxes[i][row_bits][col_bits]
                    
                    # Convert the S-box value to a 4-bit binary string and append to the result
                    s_box_substituted += format(s_box_value, '04b')

                # Apply a P permutation to the result
                p_box_result = [s_box_substituted[i - 1] for i in p_box_table]

                # Convert LPT to a list of bits for the XOR operation
                lpt_list = list(lpt)

                # Perform XOR operation
                new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]

                # Convert the result back to a string for better visualization
                new_rpt_str = ''.join(new_rpt)

                # Update LPT and RPT for the next round
                lpt = rpt
                rpt = new_rpt_str

            # At this point, 'lpt' and 'rpt' contain the final left and right halves after 16 rounds

            # After the final round, reverse the last swap
            final_result = rpt + lpt

            # Perform the final permutation (IP-1)
            final_cipher = [final_result[ip_inverse_table[i] - 1] for i in range(64)]

            # Convert the result back to a string for better visualization
            final_cipher_str = ''.join(final_cipher)

            if len(final_cipher_str) % 64 != 0:
                raise ValueError("Final cipher length must be a multiple of 64 bits.")

            # Convert binary cipher to ascii
            final_cipher_ascii = binary_to_ascii(final_cipher_str)

            concatenated_output += final_cipher_ascii
        file.write(concatenated_output)

        return concatenated_output

           
def decryption(input_file, output_file, key):
    # Read the content of the input file
    with open(input_file, 'r') as file:
        final_cipher = file.read()
        final_cipher = ascii_to_binary(final_cipher)



    # Initialize lists to store round keys
    round_keys = generate_round_keys(key)
    
        # Check if the final cipher is a multiple of 64 bits
    if len(final_cipher) % 64 != 0:
        raise ValueError("Final cipher length must be a multiple of 64 bits.")


    # Apply Initial Permutation

    ip_dec_result_str = ip_on_binary_rep(final_cipher)

    ip_dec_result_str1 = divide_into_sixty_fours(ip_dec_result_str)

    concatenated_output = ''
    with open(output_file, 'w') as file:
        for ip_dec_result1 in ip_dec_result_str1:

            lpt = ip_dec_result1[:32]
            rpt = ip_dec_result1[32:]

            for round_num in range(16):
                # Perform expansion (32 bits to 48 bits)
                expanded_result = [rpt[i - 1] for i in e_box_table]
            
                # Convert the result back to a string for better visualization
                expanded_result_str = ''.join(expanded_result)
            
                # Round key for the current round
                round_key_str = round_keys[15-round_num]
            
                # XOR between key and expanded result 
                xor_result_str = ''
                for i in range(48):
                    xor_result_str += str(int(expanded_result_str[i]) ^ int(round_key_str[i]))
            
                # Split the 48-bit string into 8 groups of 6 bits each
                six_bit_groups = [xor_result_str[i:i+6] for i in range(0, 48, 6)]
            
                # Initialize the substituted bits string
                s_box_substituted = ''
            
                # Apply S-box substitution for each 6-bit group
                for i in range(8):
                    # Extract the row and column bits
                    row_bits = int(six_bit_groups[i][0] + six_bit_groups[i][-1], 2)
                    col_bits = int(six_bit_groups[i][1:-1], 2)
            
                    # Lookup the S-box value
                    s_box_value = s_boxes[i][row_bits][col_bits]
                    
                    # Convert the S-box value to a 4-bit binary string and append to the result
                    s_box_substituted += format(s_box_value, '04b')
            
                # Apply a P permutation to the result
                p_box_result = [s_box_substituted[i - 1] for i in p_box_table]
            
                # Convert LPT to a list of bits for the XOR operation
                lpt_list = list(lpt)
            
                # Perform XOR operation
                new_rpt = [str(int(lpt_list[i]) ^ int(p_box_result[i])) for i in range(32)]
            
                # Update LPT and RPT for the next round
                lpt = rpt
                rpt = ''.join(new_rpt)
            
            final_result = rpt + lpt
            # Perform the final permutation (IP-1)
            final_cipher = [final_result[ip_inverse_table[i] - 1] for i in range(64)]
            
            # Convert the result back to a string for better visualization
            final_cipher_str = ''.join(final_cipher)
            
            # Convert binary cipher to ascii
            final_cipher_ascii = binary_to_ascii(final_cipher_str)

            concatenated_output += final_cipher_ascii
            
            # Write the decrypted content to the output file
        file.write(concatenated_output)

            
        return concatenated_output

def main():
    # User input for file paths and password
    input_file = "DES-test2024.txt"
    output_file_encrypted = 'encryptedf.txt'
    output_file_decrypted ="decryptedf.txt"
    password = input("Enter the password for encryption and decryption: ")

    # Encrypt the file
    encrypted_text = encryption(input_file, output_file_encrypted, password)
    print("Encryption completed successfully.")

    # Decrypt the file
    decrypted_text = decryption(output_file_encrypted, output_file_decrypted, password)
    print("Decryption completed successfully.")

if __name__ == "__main__":
    main()
