# (Device 1 - Bertindak sebagai Server "B" yang Mendengarkan)
import socket, json, sys, time
from des_scratch import DESFromScratch # Impor DES Anda

# --- TAMBAHKAN IMPOR UNTUK RSA ---
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
# -----------------------------------

# --- KONFIGURASI SERVER ---
HOST = "0.0.0.0"
PORT = 5000
TIMESTAMP_WINDOW = 10 

# --- HAPUS KUNCI HARDCODED DAN OBJEK DES LAMA ---
# KEY_A_TO_B = b"TryThis1" # HAPUS
# KEY_B_TO_A = b"TryThis2" # HAPUS
# des_from_A = ... # HAPUS
# des_to_A = ... # HAPUS
# Kita akan membuat satu objek 'des_cipher' setelah key exchange

# --- FUNGSI UTILITAS JARINGAN (JSON) ---
# (Salin fungsi recv_json_line dan send_json_line Anda ke sini...
# ... tidak ada perubahan pada fungsi-fungsi ini)

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

# --- FUNGSI UTAMA SERVER (DIMODIFIKASI) ---

def main():
    print(f"[B] Server (Device 1) siap.")
    
    # --- 1. GENERATE RSA KEY PAIR ---
    # Sesuai teori KI 12.pdf, server membuat public/private key pair
    try:
        rsa_key = RSA.generate(2048) # 2048 bits
        private_key = rsa_key
        public_key_pem = rsa_key.publickey().export_key() # Format PEM untuk dikirim
        print("[B] RSA key pair (2048-bit) telah di-generate.")
    except Exception as e:
        print(f"[B] ERROR: Gagal generate RSA key: {e}")
        sys.exit(1)

    print(f"[B] Mendengarkan di {HOST}:{PORT}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        
        conn, addr = s.accept()
        
        with conn:
            print(f"[B] BERHASIL: Terhubung dengan client {addr}")
            
            # --- 2. PROSES KEY EXCHANGE (ALUR BARU) ---
            try:
                # Langkah 1: Kirim Kunci Publik (PU_B) ke Client
                conn.sendall(public_key_pem)
                print(f"[B] Kunci publik RSA telah dikirim ke {addr}.")

                # Langkah 2: Terima Kunci DES yang Dienkripsi
                # Ukuran 256 byte karena RSA 2048-bit mengenkripsi ke 256 byte
                encrypted_session_key = conn.recv(256) 
                if not encrypted_session_key:
                    raise ConnectionError("Client terputus sebelum mengirim session key.")
                
                # Langkah 3: Dekripsi Session Key menggunakan Private Key (PR_B)
                cipher_rsa = PKCS1_OAEP.new(private_key)
                session_key = cipher_rsa.decrypt(encrypted_session_key)

                if len(session_key) != 8:
                    raise ValueError("Session key yang diterima bukan 8 byte!")

                print(f"[B] Session key DES diterima (hex): {session_key.hex()}")

                # Langkah 4: Inisialisasi DES Cipher dengan session key
                des_cipher = DESFromScratch(session_key)
                print("[B] Objek DES diinisialisasi. Komunikasi aman siap.")
                
                # Langkah 5: Kirim ACK ke client
                conn.sendall(b"KEY_OK")

            except Exception as e:
                print(f"[B] ERROR saat Key Exchange: {e}")
                return # Tutup koneksi jika key exchange gagal
            
            # --- 3. LOOP CHATTING UTAMA (MODIFIKASI) ---
            # Sekarang hanya menggunakan SATU 'des_cipher'
            
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

                    # Enkripsi balasan menggunakan 'des_cipher' yang sama
                    ct_reply = des_cipher.encrypt(plaintext_json_reply)

                    print(f"    [+] Plaintext (JSON): {plaintext_json_reply}")
                    print(f"    [+] Ciphertext (Hex): {ct_reply.hex().upper()}")

                    # 10. KIRIM BALASAN TERENKRIPSI
                    send_json_line(conn, {
                        "type":"cipher_from_B",
                        "hex": ct_reply.hex()
                    })
                    print("[B] Balasan terenkripsi terkirim.")

                # --- BLOK PENANGANAN ERROR ---
                except json.JSONDecodeError as e:
                    print(f"[B] ERROR: Kunci salah. Gagal parse JSON hasil dekripsi. Error: {e}")
                except (ValueError, TypeError) as e:
                    print(f"[B] ERROR: Kunci salah. Gagal dekripsi/padding. Error: {e}")
                except Exception as e:
                    print(f"[B] ERROR: Terjadi error tak terduga: {e}")
                    continue 

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[B] Server dihentikan.")
    except Exception as e:
        print(f"[B] SERVER CRASHED (diluar loop): {e}")