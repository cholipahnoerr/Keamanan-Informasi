# Ini adalah file: client_A.py
# (Device 2 - Bertindak sebagai Client "A" yang Menghubungi)

import socket, json, sys, time
from des_scratch import DESFromScratch # Mengimpor modul DES yang kita buat

# --- KONFIGURASI CLIENT ---
# PENTING: Ganti ini ke IP LOKAL dari Device 1 (Server)
SERVER_IP = "10.58.242.162" # Sesuaikan IP server.
SERVER_PORT = 5000

# Kunci HARUS SAMA PERSIS dengan di server
KEY_A_TO_B = b"12345678" # Kunci untuk MENGENKRIPSI pesan ke Server B
KEY_B_TO_A = b"87654321" # Kunci untuk MENDEKRIPSI balasan dari Server B

# --- INISIALISASI OBJEK DES ---
# Urutannya kebalikan dari server
try:
    # Objek ini disiapkan untuk enkripsi (menggunakan KEY_A_TO_B)
    des_to_B   = DESFromScratch(KEY_A_TO_B)
    # Objek ini disiapkan untuk dekripsi (menggunakan KEY_B_TO_A)
    des_from_B = DESFromScratch(KEY_B_TO_A)
except Exception as e:
    print(f"[ERROR] Gagal menginisialisasi DES. Cek S_BOXES atau panjang kunci. Error: {e}")
    sys.exit(1)
    
# --- FUNGSI UTILITAS JARINGAN (JSON) ---
# (Fungsi ini identik dengan yang ada di server)

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

# --- FUNGSI UTAMA CLIENT ---

def main():
    print(f"[A] Client (Device 2) siap.")
    
    # 1. SETUP & KONEKSI SOCKET
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[A] Menghubungkan ke {SERVER_IP}:{SERVER_PORT} ...")
        # .connect() mencoba menghubungi server
        sock.connect((SERVER_IP, SERVER_PORT))
        print("[A] Berhasil terhubung ke server!")
    except Exception as e:
        print(f"[A] GAGAL terhubung ke server. Pastikan IP benar & server berjalan. Error: {e}")
        return

    # 2. LOOP CHATTING UTAMA
    with sock:
        while True:
            try:
                # 3. MINTA INPUT & SIAPKAN PESAN
                msg = input("\n[A] Ketik pesan (plain): ")
                if msg == "": # Keluar jika input kosong
                    break

                # 4. BUAT PAKET PLAINTEXT (JSON)
                # Bungkus pesan asli + timestamp ke dalam dict
                current_time = int(time.time())
                packet_to_encrypt = {
                    "msg": msg,
                    "ts": current_time # 'ts' untuk anti-replay attack
                }
                # Ubah dict ke string JSON (ini yg akan dienkripsi)
                plaintext_json = json.dumps(packet_to_encrypt)

                # 5. ENKRIPSI PESAN
                ct = des_to_B.encrypt(plaintext_json)
                
                # Blok demo: Menampilkan plaintext & ciphertext sebelum dikirim
                print(f"   [+] Plaintext (JSON): {plaintext_json}")
                print(f"   [+] Ciphertext (Hex): {ct.hex().upper()}")

                # 6. KIRIM PESAN TERENKRIPSI KE SERVER
                send_json_line(sock, {
                    "type": "cipher_from_A",
                    "hex": ct.hex()
                })
                print("[A] Mengirim pesan terenkripsi...")

                # 7. MENERIMA BALASAN
                # .recv_json_line() adalah BLOKING -> program berhenti di sini menunggu balasan
                print("[A] Menunggu balasan server...")
                resp = recv_json_line(sock)
                if resp is None:
                    print("[A] Server menutup koneksi.")
                    break
                
                # Cek protokol balasan
                if resp.get("type") != "cipher_from_B":
                    print("[A] Respon tidak valid:", resp)
                    continue

                # 8. DEKRIPSI BALASAN
                decrypted_payload = des_from_B.decrypt(bytes.fromhex(resp["hex"]))
                
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