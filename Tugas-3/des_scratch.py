# Modul ini berisi implementasi lengkap algoritma DES dari nol.

# --- KONSTANTA TABEL PERMUTASI & SUBSTITUSI DES ---
# Tabel-tabel ini adalah bagian standar dari algoritma DES.

# Initial Permutation (IP): Mengacak blok plaintext 64-bit di awal.
IP = [58, 50, 42, 34, 26, 18, 10, 2,
      60, 52, 44, 36, 28, 20, 12, 4,
      62, 54, 46, 38, 30, 22, 14, 6,
      64, 56, 48, 40, 32, 24, 16, 8,
      57, 49, 41, 33, 25, 17, 9, 1,
      59, 51, 43, 35, 27, 19, 11, 3,
      61, 53, 45, 37, 29, 21, 13, 5,
      63, 55, 47, 39, 31, 23, 15, 7]

# Final Permutation (FP): Invers dari IP, mengembalikan blok ke urutan semula di akhir.
FP = [40, 8, 48, 16, 56, 24, 64, 32,
      39, 7, 47, 15, 55, 23, 63, 31,
      38, 6, 46, 14, 54, 22, 62, 30,
      37, 5, 45, 13, 53, 21, 61, 29,
      36, 4, 44, 12, 52, 20, 60, 28,
      35, 3, 43, 11, 51, 19, 59, 27,
      34, 2, 42, 10, 50, 18, 58, 26,
      33, 1, 41, 9, 49, 17, 57, 25]

# Expansion (E): Memperluas blok R-half 32-bit menjadi 48-bit agar bisa di-XOR dgn subkey 48-bit.
E = [32, 1, 2, 3, 4, 5,
     4, 5, 6, 7, 8, 9,
     8, 9, 10, 11, 12, 13,
     12, 13, 14, 15, 16, 17,
     16, 17, 18, 19, 20, 21,
     20, 21, 22, 23, 24, 25,
     24, 25, 26, 27, 28, 29,
     28, 29, 30, 31, 32, 1]

# Permuted Choice 1 (PC1): Membuang bit paritas dari kunci 64-bit dan mengacaknya menjadi 56-bit.
PC1 = [57, 49, 41, 33, 25, 17, 9,
       1, 58, 50, 42, 34, 26, 18,
       10, 2, 59, 51, 43, 35, 27,
       19, 11, 3, 60, 52, 44, 36,
       63, 55, 47, 39, 31, 23, 15,
       7, 62, 54, 46, 38, 30, 22,
       14, 6, 61, 53, 45, 37, 29,
       21, 13, 5, 28, 20, 12, 4]

# Permuted Choice 2 (PC2): Mengompres kunci 56-bit (C+D) menjadi subkey 48-bit untuk ronde ini.
PC2 = [14, 17, 11, 24, 1, 5,
       3, 28, 15, 6, 21, 10,
       23, 19, 12, 4, 26, 8,
       16, 7, 27, 20, 13, 2,
       41, 52, 31, 37, 47, 55,
       30, 40, 51, 45, 33, 48,
       44, 49, 39, 56, 34, 53,
       46, 42, 50, 36, 29, 32]

# SHIFT_SCHEDULE: Menentukan berapa kali C dan D digeser (circular left shift) per ronde.
SHIFT_SCHEDULE = [1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1]

# S-Boxes (Substitution Boxes): Jantung dari keamanan DES.
# Mengubah input 6-bit menjadi output 4-bit secara non-linear.
# CATATAN: Versi di bawah ini SUDAH DIPERBAIKI (bug sintaks Anda telah dikoreksi).
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

# Permutation (P): Mengacak output 32-bit dari S-Box.
P = [16, 7, 20, 21, 29, 12, 28, 17,
     1, 15, 23, 26, 5, 18, 31, 10,
     2, 8, 24, 14, 32, 27, 3, 9,
     19, 13, 30, 6, 22, 11, 4, 25]

# --- KELAS UTAMA DES ---
# Kelas ini membungkus semua logika DES.
class DESFromScratch:
    
    # Konstruktor: Dipanggil saat 'DESFromScratch(kunci)' dibuat.
    def __init__(self, key):
        # 1. Validasi Kunci: Kunci DES HARUS 8 byte (64 bit).
        if len(key) != 8:
            raise ValueError("Kunci harus tepat 8 byte (64 bit).")
        self.key = key
        
        # 2. Generate Subkeys: Langsung buat 16 subkey saat objek dibuat.
        self.subkeys = self._generate_subkeys()

    # --- FUNGSI UTILITAS INTERNAL (HELPER) ---

    def _permute(self, block, table):
        """Melakukan permutasi pada list 'block' berdasarkan 'table'."""
        return [block[p - 1] for p in table]

    def _bytes_to_bits(self, data):
        """Mengubah data bytes (misal: b'tes') menjadi list bit [0,1,1,0,...]."""
        return [int(bit) for byte in data for bit in format(byte, '08b')]

    def _bits_to_bytes(self, bits):
        """Mengubah list bit [0,1,1,0,...] kembali menjadi data bytes."""
        byte_list = []
        for i in range(0, len(bits), 8):
            byte_val = int("".join(map(str, bits[i:i+8])), 2)
            byte_list.append(byte_val)
        return bytes(byte_list)

    def _xor(self, bits1, bits2):
        """Melakukan operasi XOR bit-per-bit pada dua list."""
        return [b1 ^ b2 for b1, b2 in zip(bits1, bits2)]

    def _left_shift(self, bits, n):
        """Melakukan pergeseran kiri sirkular (circular left shift) sebanyak n."""
        return bits[n:] + bits[:n]

    # --- LOGIKA KEY SCHEDULE (PEMBUATAN SUBKEY) ---
    
    def _generate_subkeys(self):
        """Menghasilkan 16 subkey 48-bit dari kunci utama 64-bit."""
        subkeys = []
        key_bits = self._bytes_to_bits(self.key)
        
        # Langkah 1: Terapkan PC-1 (64-bit -> 56-bit)
        permuted_key = self._permute(key_bits, PC1)
        
        # Langkah 2: Bagi menjadi C0 dan D0 (masing-masing 28 bit)
        C, D = permuted_key[:28], permuted_key[28:]
        
        # Lakukan 16 ronde untuk membuat 16 subkey
        for i in range(16):
            # Langkah 3: Geser C dan D ke kiri sesuai jadwal (SHIFT_SCHEDULE)
            C = self._left_shift(C, SHIFT_SCHEDULE[i])
            D = self._left_shift(D, SHIFT_SCHEDULE[i])
            
            # Langkah 4: Gabungkan C dan D, terapkan PC-2 (56-bit -> 48-bit)
            combined = C + D
            subkey = self._permute(combined, PC2)
            subkeys.append(subkey)
            
        return subkeys

    # --- FUNGSI FEISTEL (F-function) ---
    
    def _f_function(self, right_half, subkey):
        """Ini adalah jantung dari DES, fungsi Feistel (F)."""
        
        # Langkah 1: Expansion (E-Table) - (32-bit -> 48-bit)
        expanded = self._permute(right_half, E)
        
        # Langkah 2: Key Mixing - XOR hasil ekspansi dengan subkey ronde.
        xored = self._xor(expanded, subkey)
        
        # Langkah 3: Substitution (S-Boxes) - (48-bit -> 32-bit)
        # Ini adalah satu-satunya bagian non-linear dari DES.
        s_box_output = []
        for i in range(8):
            chunk = xored[i*6 : (i+1)*6] # Ambil 6 bit
            # Bit pertama & terakhir (bit 1 & 6) -> nomor baris
            row = int(str(chunk[0]) + str(chunk[5]), 2)
            # Bit tengah (bit 2-5) -> nomor kolom
            col = int("".join(map(str, chunk[1:5])), 2)
            
            # Ambil nilai 4-bit dari S-Box
            val = S_BOXES[i][row][col] 
            s_box_output.extend(list(map(int, format(val, '04b'))))
            
        # Langkah 4: Permutation (P-Box) - (32-bit -> 32-bit)
        return self._permute(s_box_output, P)

    # --- FUNGSI PEMROSESAN BLOK TUNGGAL (64-bit) ---

    def _process_block(self, block, subkeys):
        """Memproses satu blok 64-bit (enkripsi atau dekripsi)."""
        
        # Langkah 1: Initial Permutation (IP)
        block = self._permute(block, IP)
        
        # Langkah 2: Bagi menjadi L dan R (masing-masing 32 bit)
        L, R = block[:32], block[32:]
        
        # Langkah 3: Lakukan 16 Ronde Feistel
        for i in range(16):
            L_prev, R_prev = L, R  # Simpan nilai L dan R ronde sebelumnya
            
            L = R_prev # L baru = R lama
            f_result = self._f_function(R_prev, subkeys[i]) # Jalankan F-function
            R = self._xor(L_prev, f_result) # R baru = L lama XOR F(R lama, subkey)
            
        # Langkah 4: Swap Terakhir (Final Swap)
        # Setelah 16 ronde, gabungkan R dan L (bukan L dan R)
        block = R + L
        
        # Langkah 5: Final Permutation (FP)
        return self._permute(block, FP)

    # --- FUNGSI PADDING (PKCS#7) ---
    # DES bekerja pada blok 8 byte. Padding memastikan data kita kelipatan 8.

    def _pad(self, data):
        """Menambahkan byte padding agar panjang data pas kelipatan 8."""
        # Misal: data 5 byte -> pad_len = 3. Tambahkan b'\x03\x03\x03'
        pad_len = 8 - (len(data) % 8)
        padding = bytes([pad_len] * pad_len)
        return data + padding

    def _unpad(self, data):
        """Membuang byte padding dari data."""
        # Ambil byte terakhir untuk tahu berapa banyak padding
        pad_len = data[-1]
        if pad_len > 8 or pad_len == 0:
            raise ValueError("Padding tidak valid, kemungkinan kunci salah.")
        # Cek apakah padding-nya konsisten
        if any(b != pad_len for b in data[-pad_len:]):
            raise ValueError("Byte padding tidak konsisten, kemungkinan kunci salah.")
        return data[:-pad_len]

    # --- FUNGSI PUBLIK (YANG DIPANGGIL SERVER/CLIENT) ---

    def encrypt(self, plaintext: str) -> bytes:
        """Mengenkripsi string plaintext menjadi bytes ciphertext (Mode ECB)."""
        plaintext_bytes = plaintext.encode('utf-8')
        padded_plaintext = self._pad(plaintext_bytes)
        
        ciphertext = b''
        # Enkripsi per blok 8-byte (ini adalah mode ECB)
        for i in range(0, len(padded_plaintext), 8):
            block = padded_plaintext[i:i+8]
            block_bits = self._bytes_to_bits(block)
            encrypted_block_bits = self._process_block(block_bits, self.subkeys)
            ciphertext += self._bits_to_bytes(encrypted_block_bits)
        return ciphertext

    def decrypt(self, ciphertext: bytes) -> str:
        """Mendekripsi bytes ciphertext menjadi string plaintext (Mode ECB)."""
        decrypted_padded_text = b''
        
        # PENTING: Untuk dekripsi, subkey digunakan dalam urutan terbalik.
        reversed_subkeys = self.subkeys[::-1] 
        
        # Dekripsi per blok 8-byte
        for i in range(0, len(ciphertext), 8):
            block = ciphertext[i:i+8]
            block_bits = self._bytes_to_bits(block)
            decrypted_block_bits = self._process_block(block_bits, reversed_subkeys)
            decrypted_padded_text += self._bits_to_bytes(decrypted_block_bits)
        
        # Buang padding dan ubah kembali ke string
        original_text_bytes = self._unpad(decrypted_padded_text) 
        return original_text_bytes.decode('utf-8')