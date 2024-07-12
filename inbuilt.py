import itertools

from Crypto.Cipher import DES

from Crypto.Util.Padding import pad, unpad




def generate_key(user_input):

    """

    The user input is used to generate a 64-bit DES key through the process of padding or truncating.

    """

    key = pad(user_input.encode(), 8)[:8] # Ensure key is 8 bytes long

    return key




def encrypt(input_file, output_file, key):

    """

    DES-encrypts an input file and copies the output to another.

    """

    with open(input_file, 'rb') as f:

        plaintext = f.read()




    cipher = DES.new(key, DES.MODE_ECB)

    ciphertext = cipher.encrypt(pad(plaintext, DES.block_size))




    with open(output_file, 'wb') as f:

        f.write(ciphertext)




def decrypt(input_file, output_file, key):

    """

    DES-decrypts one input file and copies the output to another.

    """

    with open(input_file, 'rb') as f:

        ciphertext = f.read()




    cipher = DES.new(key, DES.MODE_ECB)

    plaintext = unpad(cipher.decrypt(ciphertext), DES.block_size)




    with open(output_file, 'w') as f:

        f.write(plaintext.decode())




def main():

    user_input = input("Enter the encryption key: ")

    key = generate_key(user_input)




    # Encrypt DES-test2024.txt and save as encrypted.txt

    encrypt('DES-test2024.txt', 'encrypted.txt', key)

    decrypt('encrypted.txt', 'decrypted.txt', key)



    print("Encryption and Decryption completed. Check encrypted.txt and decrypted.txt.")




if __name__ == "__main__":

    main()
