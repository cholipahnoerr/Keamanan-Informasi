# (Device 2 - Bertindak sebagai Client "A" yang Menghubungi)
import socket, json, sys, time
from des_scratch import DESFromScratch # Impor DES Anda

# --- TAMBAHKAN IMPOR 'os' UNTUK RANDOM KEY ---
import os 
# ---------------------------------------------

# --- KONFIGURASI CLIENT ---
SERVER_IP = input("Masukkan IP Server (Device 1): ") 
SERVER_PORT = 5000

# Objek 'des_cipher' akan dibuat SETELAH key exchange
des_cipher = None
    
# --- FUNGSI UTILITAS JARINGAN (JSON) ---
# (Fungsi recv_json_line dan send_json_line SAMA PERSIS, salin ke sini)
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

# --- FUNGSI KEY EXCHANGE (BARU) ---
def perform_key_exchange(sock):
    """Melakukan key exchange menggunakan RSA contoh dari kuliah."""
    global des_cipher
    try:
        # Langkah 1: Terima Kunci Publik (PU_B) dari Server
        incoming = recv_json_line(sock)
        if not incoming or "n" not in incoming or "e" not in incoming:
            raise ConnectionError("Gagal menerima public key dari server.")
        
        rsa_n = incoming["n"]
        rsa_e = incoming["e"]
        print(f"[A] Kunci publik server diterima: n={rsa_n}, e={rsa_e}")

        # Langkah 2: Buat Session Key (8-byte acak untuk DES)
        session_key = os.urandom(8) # 8 byte (64 bit) acak
        print(f"[A] Session key DES di-generate (hex): {session_key.hex()}")

        # Langkah 3: Enkripsi Session Key (M) dengan Public Key (e, n)
        # Pisahkan 8 byte menjadi 16 nibble (4-bit)
        key_parts_to_encrypt = []
        for byte in session_key: # 'byte' akan menjadi integer (mis: 224)
            high_nibble = byte >> 4    # misal: 224 >> 4  = 14 (0x0e)
            low_nibble = byte & 0x0F # misal: 224 & 15 = 0  (0x00)
            key_parts_to_encrypt.append(high_nibble)
            key_parts_to_encrypt.append(low_nibble)
            
        print(f"[A] Kunci dipecah menjadi 16 nibble: {key_parts_to_encrypt}")

        # Enkripsi 16 nibble satu per satu
        # C = M^e mod n
        encrypted_key_parts = []
        for part in key_parts_to_encrypt: # 'part' dijamin 0-15
            c = pow(part, rsa_e, rsa_n)
            encrypted_key_parts.append(c)

        print(f"[A] 16 bagian kunci terenkripsi: {encrypted_key_parts}")

        # Langkah 4: Kirim 16 bagian kunci terenkripsi ke Server
        send_json_line(sock, {"key_parts": encrypted_key_parts})
        print("[A] Session key terenkripsi telah dikirim ke server.")

        # Langkah 5: Tunggu ACK dari server
        ack = recv_json_line(sock)
        if not ack or ack.get("status") != "KEY_OK":
            raise ConnectionError(f"Gagal menerima ACK kunci. Server: {ack.get('error', 'Unknown error')}")
        
        # Langkah 6: Inisialisasi DES Cipher dengan session key
        des_cipher = DESFromScratch(session_key)
        print("[A] Objek DES diinisialisasi. Komunikasi aman siap.")
        return True

    except Exception as e:
        print(f"[A] ERROR saat Key Exchange: {e}")
        return False
        
# --- FUNGSI UTAMA CLIENT ---
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
        # --- 2. LAKUKAN KEY EXCHANGE ---
        if not perform_key_exchange(sock):
            print("[A] Key exchange gagal. Menutup koneksi.")
            return # Tutup koneksi jika key exchange gagal

        # --- 3. LOOP CHATTING UTAMA ---
        # (Loop ini SAMA PERSIS seperti sebelumnya, tidak perlu diubah)
        # Dia akan menggunakan variabel 'des_cipher' global
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

                # 5. ENKRIPSI PESAN
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

                # 8. DEKRIPSI BALASAN
                decrypted_payload = des_cipher.decrypt(bytes.fromhex(resp["hex"]))
                reply_packet = json.loads(decrypted_payload)
                
                # 9. TAMPILKAN BALASAN (SUKSES)
                print(f"[A] Balasan Server (dekrip): {reply_packet['msg']}")

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
