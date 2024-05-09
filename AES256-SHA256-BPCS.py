import os
import hashlib
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import numpy as np
import cv2

# Fungsi untuk mengenkripsi pesan menggunakan AES256 dengan PKCS7 padding
def encrypt_message(message, key):
    # Padding pesan dengan PKCS7
    block_size = AES.block_size
    padding_length = block_size - len(message) % block_size
    padded_message = message + bytes([padding_length]) * padding_length

    # Melakukan enkripsi AES256
    cipher = AES.new(key, AES.MODE_CBC)
    ciphertext = cipher.encrypt(padded_message)
    return cipher.iv, ciphertext


# Fungsi untuk mendekripsi pesan yang dienkripsi menggunakan AES256 dengan PKCS7 padding
def decrypt_message(ciphertext, key, iv):
    # Melakukan dekripsi AES256
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(ciphertext)

    # Menghapus padding PKCS7
    padding_length = decrypted_message[-1]
    decrypted_message = decrypted_message[:-padding_length]

    return decrypted_message


# Fungsi untuk menghitung hash SHA256 dari sebuah pesan
def calculate_hash(message):
    return hashlib.sha256(message).digest()


# Fungsi utama
def main():
    while True:
        print("Pilih operasi yang ingin dilakukan:")
        print("1. Enkripsi pesan")
        print("2. Dekripsi pesan")
        print("3. Keluar")
        
        choice = input("Masukkan pilihan (1/2/3): ")
        
        if choice == '1':
            # Membaca pesan dari pengguna
            message = input("Masukkan pesan yang ingin dienkripsi: ")

            # Membaca kunci AES dari pengguna
            key = input("Masukkan kunci AES (32 bytes): ").encode('utf-8')
            if len(key) != 32:
                print("Panjang kunci harus 32 bytes.")
                continue

            # Enkripsi pesan menggunakan AES256
            iv, ciphertext = encrypt_message(message.encode('utf-8'), key)

            # Menampilkan hasil enkripsi pesan dan nilai hashnya
            print("\nEnkripsi berhasil dilakukan!")
            print("Message: ", message)
            print("Ciphertext: ", iv.hex() + ciphertext.hex())  # Menampilkan ciphertext dalam format heksadesimal
            print("Hash: ", calculate_hash(iv + ciphertext).hex(), "\n")

        elif choice == '2':
            # Membaca hasil enkripsi dari pengguna
            ciphertext_input = input("Masukkan pesan yang ingin didekripsi (dalam format heksadesimal): ")

            # Mendapatkan nilai hash dari ciphertext
            hash_value = calculate_hash(bytes.fromhex(ciphertext_input)).hex()

            # Mengonversi ciphertext dari heksadesimal menjadi bytes
            try:
                ciphertext_bytes = bytes.fromhex(ciphertext_input)
            except ValueError:
                print("Format ciphertext tidak valid. Pastikan ciphertext dalam format heksadesimal.")
                continue

            # Memisahkan IV dan ciphertext
            iv = ciphertext_bytes[:16]
            ciphertext = ciphertext_bytes[16:]

            # Membaca kunci AES dari pengguna
            key = input("Masukkan kunci AES (32 bytes): ").encode('utf-8')
            if len(key) != 32:
                print("Panjang kunci harus 32 bytes.")
                continue

            # Dekripsi pesan menggunakan AES256
            plaintext = decrypt_message(ciphertext, key, iv)

            # Menampilkan hasil dekripsi pesan, nilai hash, dan ciphertext
            print("\nDekripsi berhasil dilakukan!")
            print("Ciphertext: ", ciphertext_input)
            print("Plaintext: ", plaintext.decode('utf-8'))
            print("Hash: ", hash_value, "\n")
        
        elif choice == '3':
            print("Terima kasih telah menggunakan program ini.")
            break
        
        else:
            print("Pilihan tidak valid. Silakan pilih 1, 2, atau 3.")

if __name__ == "__main__":
    main()
