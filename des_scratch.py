# Tabel Initial Permutation (IP)
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Tabel Final Permutation (FP), merupakan invers dari IP
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Tabel Expansion (E) untuk memperluas blok 32-bit menjadi 48-bit
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# Tabel Permuted Choice 1 (PC-1) untuk Key Schedule
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Tabel Permuted Choice 2 (PC-2) untuk Key Schedule
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# Jumlah pergeseran kiri (left shift) untuk setiap ronde pada Key Schedule
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# S-Boxes (Substitution Boxes)
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
     [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]],
    # S8
    [[13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
     [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
     [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
     [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]]
]

# Tabel Permutasi (P-Box) setelah substitusi S-Box
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

class DESFromScratch:
    def __init__(self, key):
        if len(key) != 8:
            raise ValueError("Kunci harus tepat 8 byte (64 bit).")
        self.key = key
        self.subkeys = self._generate_subkeys()

    def _permute(self, block, table):
        """Melakukan permutasi pada blok berdasarkan tabel."""
        return [block[p - 1] for p in table]

    def _string_to_bits(self, text):
        """Mengubah string menjadi list of bits."""
        return [bit for char in text for bit in format(ord(char), '08b')]

    def _bytes_to_bits(self, data):
        """Mengubah bytes menjadi list of bits."""
        return [int(bit) for byte in data for bit in format(byte, '08b')]

    def _bits_to_bytes(self, bits):
        """Mengubah list of bits menjadi bytes."""
        byte_list = []
        for i in range(0, len(bits), 8):
            byte_val = int("".join(map(str, bits[i:i+8])), 2)
            byte_list.append(byte_val)
        return bytes(byte_list)

    def _xor(self, bits1, bits2):
        """Melakukan operasi XOR pada dua list of bits."""
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    def _left_shift(self, bits, n):
        """Melakukan pergeseran kiri (circular) sebanyak n."""
        return bits[n:] + bits[:n]

    def _generate_subkeys(self):
        """Menghasilkan 16 subkunci 48-bit dari kunci utama."""
        key_bits = self._bytes_to_bits(self.key)
        
        # Langkah 1: PC-1
        permuted_key = self._permute(key_bits, PC1)
        
        # Langkah 2: Bagi menjadi C0 dan D0 (masing-masing 28 bit)
        C = permuted_key[:28]
        D = permuted_key[28:]
        
        subkeys = []
        for i in range(16):
            # Langkah 3: Lakukan pergeseran kiri
            C = self._left_shift(C, SHIFT_SCHEDULE[i])
            D = self._left_shift(D, SHIFT_SCHEDULE[i])
            
            # Langkah 4: Gabungkan C dan D, lalu terapkan PC-2
            combined = C + D
            subkey = self._permute(combined, PC2)
            subkeys.append(subkey)
            
        return subkeys

    def _f_function(self, right_half, subkey):
        """Fungsi Feistel (F-function)."""
        # 1. Expansion
        expanded = self._permute(right_half, E)
        
        # 2. XOR dengan subkunci
        xored = self._xor(expanded, subkey)
        
        # 3. Substitusi S-Box
        s_box_output = []
        for i in range(8):
            chunk = xored[i*6 : (i+1)*6]
            row = int(str(chunk[0]) + str(chunk[5]), 2)
            col = int("".join(map(str, chunk[1:5])), 2)
            val = S_BOXES[i][row][col]
            s_box_output.extend(list(map(int, format(val, '04b'))))
            
        # 4. Permutasi P-Box
        permuted = self._permute(s_box_output, P)
        
        return permuted

    def _process_block(self, block, subkeys):
        """Memproses satu blok 64-bit untuk enkripsi/dekripsi."""
        # 1. Initial Permutation
        block = self._permute(block, IP)
        
        # 2. Bagi menjadi L0 dan R0
        L, R = block[:32], block[32:]
        
        # 3. 16 Ronde
        for i in range(16):
            L_prev, R_prev = L, R
            L = R_prev
            f_result = self._f_function(R_prev, subkeys[i])
            R = self._xor(L_prev, f_result)
            
        # 4. Swap terakhir
        block = R + L
        
        # 5. Final Permutation
        final_block = self._permute(block, FP)
        return final_block

    def _pad(self, data):
        """Menambahkan padding PKCS#7."""
        pad_len = 8 - (len(data) % 8)
        padding = bytes([pad_len] * pad_len)
        return data + padding

    def _unpad(self, data):
        """Menghapus padding PKCS#7."""
        pad_len = data[-1]
        return data[:-pad_len]

    def encrypt(self, plaintext):
        """Mengenkripsi plaintext (string)."""
        plaintext_bytes = plaintext.encode('utf-8')
        padded_plaintext = self._pad(plaintext_bytes)
        
        ciphertext = b''
        for i in range(0, len(padded_plaintext), 8):
            block = padded_plaintext[i:i+8]
            block_bits = self._bytes_to_bits(block)
            encrypted_block_bits = self._process_block(block_bits, self.subkeys)
            ciphertext += self._bits_to_bytes(encrypted_block_bits)
            
        return ciphertext

    def decrypt(self, ciphertext):
        """Mendekripsi ciphertext (bytes)."""
        decrypted_padded_text = b''
        reversed_subkeys = self.subkeys[::-1] # Kunci dibalik untuk dekripsi
        
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            block_bits = self._bytes_to_bits(block)
            decrypted_block_bits = self._process_block(block_bits, reversed_subkeys)
            decrypted_padded_text += self._bits_to_bytes(decrypted_block_bits)
            
        original_text_bytes = self._unpad(decrypted_padded_text)
        return original_text_bytes.decode('utf-8')


# --- PROGRAM UTAMA ---
if __name__ == "__main__":
    while True:
        print("\n=== IMPLEMENTASI DES DARI SCRATCH ===")
        print("1. Enkripsi")
        print("2. Dekripsi")
        print("3. Keluar")
        
        pilihan = input("\nPilih operasi (1-3): ")
        
        if pilihan == "3":
            print("Program selesai.")
            break
            
        elif pilihan in ["1", "2"]:
            # Input kunci (harus 8 karakter)
            while True:
                key_text = input("\nMasukkan kunci (8 karakter): ")
                if len(key_text) == 8:
                    break
                print("Error: Kunci harus tepat 8 karakter!")
            
            key_bytes = key_text.encode('utf-8')
            des_cipher = DESFromScratch(key_bytes)
            
            if pilihan == "1":
                # Proses Enkripsi
                plaintext = input("Masukkan teks yang akan dienkripsi: ")
                print("\n--- HASIL ENKRIPSI ---")
                print(f"Plaintext       : {plaintext}")
                print(f"Kunci          : {key_text}")
                ciphertext = des_cipher.encrypt(plaintext)
                print(f"Ciphertext (Hex): {ciphertext.hex()}")
                
            else:
                # Proses Dekripsi
                hex_input = input("Masukkan ciphertext (dalam format hex): ")
                try:
                    ciphertext = bytes.fromhex(hex_input)
                    decrypted_text = des_cipher.decrypt(ciphertext)
                    print("\n--- HASIL DEKRIPSI ---")
                    print(f"Ciphertext (Hex): {hex_input}")
                    print(f"Kunci          : {key_text}")
                    print(f"Hasil Dekripsi : {decrypted_text}")
                except ValueError:
                    print("Error: Format hex tidak valid!")
                    
        else:
            print("Error: Pilihan tidak valid!")