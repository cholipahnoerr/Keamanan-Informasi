# (Device 2 - Bertindak sebagai Client "A" yang Menghubungi)
import socket, json, sys, time
from des_scratch import DESFromScratch # Impor DES Anda

# --- TAMBAHKAN IMPOR UNTUK RSA ---
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes # Untuk membuat session key
# -----------------------------------

# --- KONFIGURASI CLIENT ---
SERVER_IP = input("Masukkan IP Server (Device 1): ") # Minta IP saat runtime
SERVER_PORT = 5000

# --- HAPUS KUNCI HARDCODED DAN OBJEK DES LAMA ---
# KEY_A_TO_B = b"TryThis1" # HAPUS
# KEY_B_TO_A = b"TryThis2" # HAPUS
# des_to_B = ... # HAPUS
# des_from_B = ... # HAPUS
# Kita akan membuat satu objek 'des_cipher' setelah key exchange

# --- FUNGSI UTILITAS JARINGAN (JSON) ---
# (Salin fungsi recv_json_line dan send_json_line Anda ke sini...
# ... tidak ada perubahan pada fungsi-fungsi ini)

def recv_json_line(sock):
    """Menerima data socket hingga menemukan newline (\n) & parse sebagai JSON."""
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
    line, rest = buf.split(b"\n", 1)
    return json.loads(line.decode("utf-8"))

def send_json_line(sock, obj):
    """Mengubah objek Python (dict) ke JSON, tambah newline (\n), & kirim."""
    data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    sock.sendall(data)
    
# --- FUNGSI UTAMA CLIENT (DIMODIFIKASI) ---

def main():
    print(f"[A] Client (Device 2) siap.")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[A] Menghubungkan ke {SERVER_IP}:{SERVER_PORT} ...")
        sock.connect((SERVER_IP, SERVER_PORT))
        print("[A] Berhasil terhubung ke server!")
    except Exception as e:
        print(f"[A] GAGAL terhubung ke server. Error: {e}")
        return

    with sock:
        # --- 2. PROSES KEY EXCHANGE (ALUR BARU) ---
        try:
            # Langkah 1: Terima Kunci Publik (PU_B) dari Server
            # Ukuran 1024 cukup untuk menampung PEM key
            public_key_pem = sock.recv(2048) 
            if not public_key_pem:
                raise ConnectionError("Server terputus sebelum mengirim public key.")
            
            # Import kunci PEM menjadi objek RSA
            server_pub_key = RSA.import_key(public_key_pem)
            print("[A] Kunci publik server diterima dan di-load.")

            # Langkah 2: Buat Session Key (8-byte acak untuk DES)
            session_key = get_random_bytes(8)
            print(f"[A] Session key DES di-generate (hex): {session_key.hex()}")

            # Langkah 3: Enkripsi Session Key (M) dengan Public Key (PU_B)
            cipher_rsa = PKCS1_OAEP.new(server_pub_key)
            encrypted_session_key = cipher_rsa.encrypt(session_key)

            # Langkah 4: Kirim Session Key terenkripsi ke Server
            sock.sendall(encrypted_session_key)
            print("[A] Session key terenkripsi telah dikirim ke server.")

            # Langkah 5: Tunggu ACK dari server
            ack = sock.recv(1024)
            if ack != b"KEY_OK":
                raise ConnectionError("Gagal menerima ACK kunci dari server.")
            
            # Langkah 6: Inisialisasi DES Cipher dengan session key
            des_cipher = DESFromScratch(session_key)
            print("[A] Objek DES diinisialisasi. Komunikasi aman siap.")

        except Exception as e:
            print(f"[A] ERROR saat Key Exchange: {e}")
            return # Tutup koneksi jika key exchange gagal

        # --- 3. LOOP CHATTING UTAMA (MODIFIKASI) ---
        # Sekarang hanya menggunakan SATU 'des_cipher'

        while True:
            try:
                # 3. MINTA INPUT & SIAPKAN PESAN
                msg = input("\n[A] Ketik pesan (plain): ")
                if msg == "": 
                    break

                # 4. BUAT PAKET PLAINTEXT (JSON)
                current_time = int(time.time())
                packet_to_encrypt = {
                    "msg": msg,
                    "ts": current_time 
                }
                plaintext_json = json.dumps(packet_to_encrypt)

                # 5. ENKRIPSI PESAN (menggunakan 'des_cipher')
                ct = des_cipher.encrypt(plaintext_json)
                
                print(f"    [+] Plaintext (JSON): {plaintext_json}")
                print(f"    [+] Ciphertext (Hex): {ct.hex().upper()}")

                # 6. KIRIM PESAN TERENKRIPSI KE SERVER
                send_json_line(sock, {
                    "type": "cipher_from_A",
                    "hex": ct.hex()
                })
                print("[A] Mengirim pesan terenkripsi...")

                # 7. MENERIMA BALASAN
                print("[A] Menunggu balasan server...")
                resp = recv_json_line(sock)
                if resp is None:
                    print("[A] Server menutup koneksi.")
                    break
                
                if resp.get("type") != "cipher_from_B":
                    print("[A] Respon tidak valid:", resp)
                    continue

                # 8. DEKRIPSI BALASAN (menggunakan 'des_cipher')
                decrypted_payload = des_cipher.decrypt(bytes.fromhex(resp["hex"]))
                
                # Parse JSON hasil dekripsi
                reply_packet = json.loads(decrypted_payload)
                
                # 9. TAMPILKAN BALASAN (SUKSES)
                print(f"[A] Balasan Server (dekrip): {reply_packet['msg']}")

            # --- BLOK PENANGANAN ERROR ---
            except (ConnectionResetError, BrokenPipeError):
                print("[A] Koneksi terputus (server mungkin crash/berhenti).")
                break
            except Exception as e:
                print(f"[A] Terjadi error: {e}")
                break

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[A] Keluar.")