# (Device 1 - Bertindak sebagai Server "B" yang Mendengarkan)
import socket, json, sys, time
from des_scratch import DESFromScratch # Impor DES Anda
# TIDAK ADA impor 'Crypto' lagi

# --- KONFIGURASI SERVER ---
HOST = "0.0.0.0"
PORT = 5000
TIMESTAMP_WINDOW = 10 

# --- KUNCI RSA DARI CONTOH KULIAH (KI 12.pdf, hal 20) ---
# p=17, q=11
RSA_N = 187  # Modulus (n = p*q) [cite: 2155]
RSA_E = 7    # Public Exponent (e) [cite: 2163]
RSA_D = 23   # Private Exponent (d) [cite: 2164]
# --------------------------------------------------------

# Objek 'des_cipher' akan dibuat SETELAH key exchange
des_cipher = None

# --- FUNGSI UTILITAS JARINGAN (JSON) ---
# (Fungsi recv_json_line dan send_json_line SAMA PERSIS, salin ke sini)
def recv_json_line(conn):
    """Menerima data socket hingga menemukan newline (\n) & parse sebagai JSON."""
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk: 
            return None
        buf += chunk
    line, rest = buf.split(b"\n", 1) 
    return json.loads(line.decode("utf-8"))

def send_json_line(conn, obj):
    """Mengubah objek Python (dict) ke JSON, tambah newline (\n), & kirim."""
    try:
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        conn.sendall(data)
    except Exception as e:
        print(f"[B] Gagal mengirim balasan: {e}")

# --- FUNGSI KEY EXCHANGE (BARU) ---
def perform_key_exchange(conn):
    """Melakukan key exchange menggunakan RSA contoh dari kuliah."""
    global des_cipher # Kita akan set variabel global
    try:
        # Langkah 1: Kirim Kunci Publik (PU={e,n}) ke Client
        public_key_data = {"n": RSA_N, "e": RSA_E}
        send_json_line(conn, public_key_data)
        print(f"[B] Kunci publik RSA {public_key_data} telah dikirim.")

        # Langkah 2: Terima Kunci DES yang dienkripsi (16 bagian)
        incoming = recv_json_line(conn)
        if not incoming or "key_parts" not in incoming:
            raise ConnectionError("Client terputus/gagal mengirim session key.")

        encrypted_key_parts = incoming["key_parts"]
        if len(encrypted_key_parts) != 16: # HARUS TEPAT 16 BAGIAN
            raise ValueError(f"Session key yang diterima bukan 16 bagian (menerima {len(encrypted_key_parts)}).")
        
        print(f"[B] Menerima 16 bagian kunci terenkripsi (nibbles)...")

        # Langkah 3: Dekripsi 16 bagian kunci menggunakan Private Key (d, n)
        # M = C^d mod n
        decrypted_nibbles = []
        for c in encrypted_key_parts:
            # Gunakan pow(c, d, n) -> implementasi "Square & Multiply"
            m = pow(c, RSA_D, RSA_N) 
            decrypted_nibbles.append(m)
        
        # Langkah 4: Rekonstruksi 8 byte dari 16 nibble
        session_key_bytes = []
        for i in range(0, 16, 2): # Ambil 2 nibble sekaligus
            high_nibble = decrypted_nibbles[i]
            low_nibble = decrypted_nibbles[i+1]
            
            # Gabungkan 2 nibble (4-bit) menjadi 1 byte (8-bit)
            byte_val = (high_nibble << 4) | low_nibble 
            session_key_bytes.append(byte_val)
            
        session_key = bytes(session_key_bytes)
        print(f"[B] Session key DES didekripsi (hex): {session_key.hex()}")

        # Langkah 5: Inisialisasi DES Cipher dengan session key
        des_cipher = DESFromScratch(session_key)
        print("[B] Objek DES diinisialisasi. Komunikasi aman siap.")
        
        # Langkah 6: Kirim ACK ke client
        send_json_line(conn, {"status": "KEY_OK"})
        return True

    except Exception as e:
        print(f"[B] ERROR saat Key Exchange: {e}")
        try:
            send_json_line(conn, {"status": "KEY_FAIL", "error": str(e)})
        except:
            pass 
        return False
    
# --- FUNGSI UTAMA SERVER ---
def main():
    print(f"[B] Server (Device 1) siap.")
    print(f"[B] Kunci RSA di-load: n={RSA_N}, e={RSA_E}, d={RSA_D}")
    print(f"[B] Mendengarkan di {HOST}:{PORT}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        
        conn, addr = s.accept()
        
        with conn:
            print(f"[B] BERHASIL: Terhubung dengan client {addr}")
            
            # --- 2. LAKUKAN KEY EXCHANGE ---
            if not perform_key_exchange(conn):
                print("[B] Key exchange gagal. Menutup koneksi.")
                return # Tutup koneksi jika key exchange gagal
            
            # --- 3. LOOP CHATTING UTAMA ---
            # (Loop ini SAMA PERSIS seperti sebelumnya, tidak perlu diubah)
            # Dia akan menggunakan variabel 'des_cipher' global
            while True:
                try:
                    # 4. MENERIMA PESAN DARI CLIENT
                    incoming = recv_json_line(conn)
                    if incoming is None:
                        print("[B] INFO: Client menutup koneksi.")
                        break 

                    if incoming.get("type") != "cipher_from_A":
                        print(f"[B] WARNING: Tipe pesan tidak valid.")
                        continue

                    hex_ct = incoming.get("hex")
                    if not hex_ct:
                        print("[B] WARNING: Pesan tidak memiliki 'hex' data.")
                        continue
                        
                    # 5. DEKRIPSI PAYLOAD (menggunakan 'des_cipher')
                    decrypted_payload = des_cipher.decrypt(bytes.fromhex(hex_ct))
                    packet = json.loads(decrypted_payload)
                    
                    # 6. VALIDASI KEAMANAN (ANTI-REPLAY ATTACK)
                    server_time = int(time.time())
                    client_time = packet.get("ts")
                    
                    if not isinstance(client_time, int):
                        raise ValueError("Timestamp tidak valid.")

                    time_diff = abs(server_time - client_time)
                    if time_diff > TIMESTAMP_WINDOW:
                        print(f"[B] REJECT: Replay attack terdeteksi. Pesan ditolak.")
                        continue
                    
                    # 7. TAMPILKAN PESAN (SUKSES)
                    pt = packet.get("msg")
                    print(f"\n[B] Pesan dari {addr} (dekrip): {pt}")

                    # 8. MEMBUAT BALASAN
                    reply = input("[B] Balasan Anda (plain): ")
                    
                    # 9. SIAPKAN & ENKRIPSI BALASAN (menggunakan 'des_cipher')
                    current_time = int(time.time())
                    reply_packet_to_encrypt = {
                        "msg": reply,
                        "ts": current_time 
                    }
                    plaintext_json_reply = json.dumps(reply_packet_to_encrypt)
                    ct_reply = des_cipher.encrypt(plaintext_json_reply)

                    print(f"    [+] Plaintext (JSON): {plaintext_json_reply}")
                    print(f"    [+] Ciphertext (Hex): {ct_reply.hex().upper()}")

                    # 10. KIRIM BALASAN TERENKRIPSI
                    send_json_line(conn, {
                        "type":"cipher_from_B",
                        "hex": ct_reply.hex()
                    })
                    print("[B] Balasan terenkripsi terkirim.")

                except json.JSONDecodeError as e:
                    print(f"[B] ERROR: Kunci salah/data korup. Gagal parse JSON hasil dekripsi. Error: {e}")
                except (ValueError, TypeError) as e:
                    print(f"[B] ERROR: Kunci salah/data korup. Gagal dekripsi/padding. Error: {e}")
                except Exception as e:
                    print(f"[B] ERROR: Terjadi error tak terduga: {e}")
                    continue 

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[B] Server dihentikan.")
