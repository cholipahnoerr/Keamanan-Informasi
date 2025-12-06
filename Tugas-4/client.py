# client.py
# (Device 2 - Client "A" yang Mengirim & Menandatangani)
import socket, json, sys, time, os, threading
from des_scratch import DESFromScratch # Pastikan file des_scratch.py ada di folder yang sama

# --- KONFIGURASI CLIENT ---
# IP Server bisa di-hardcode atau input user.
# Jika testing lokal, masukkan 127.0.0.1 saat diminta.
SERVER_IP = input("Masukkan IP Server (Hub): ") 
SERVER_PORT = 5000

# --- KUNCI RSA CLIENT (A) ---
# Kita menambahkan ini untuk fitur DIGITAL SIGNATURE.
# Sesuai materi KI 12, Client butuh Private Key untuk menandatangani (Sign).
# Contoh kunci kecil: n=221 (p=13, q=17), e=5, d=77
CLIENT_N = 221
CLIENT_E = 5
CLIENT_D = 77  # Private Key (RAHASIA - Jangan disebar)

# Objek DES akan diisi setelah handshake sukses
des_cipher = None
    
# --- FUNGSI UTILITAS JARINGAN (JSON) ---
def recv_json_line(sock):
    """Menerima data JSON yang diakhiri baris baru."""
    buf = b""
    while b"\n" not in buf:
        try:
            chunk = sock.recv(4096)
            if not chunk: return None
            buf += chunk
        except ConnectionResetError:
            return None
    line, rest = buf.split(b"\n", 1)
    return json.loads(line.decode("utf-8"))

def send_json_line(sock, obj):
    """Mengirim dictionary sebagai JSON string dengan newline."""
    try:
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        sock.sendall(data)
    except (ConnectionResetError, BrokenPipeError):
        pass 

# --- FUNGSI KEY EXCHANGE DENGAN SIGNATURE (MODIFIKASI UTAMA) ---
def perform_authenticated_key_exchange(sock):
    global des_cipher
    try:
        # 1. Terima Public Key Server
        incoming = recv_json_line(sock)
        if not incoming or "n" not in incoming:
            raise ConnectionError("Gagal menerima Public Key Server.")
            
        server_n = incoming["n"]
        server_e = incoming["e"]
        print(f"[A] Public Key Server diterima: n={server_n}, e={server_e}")

        # 2. Generate Session Key (DES) - Random 8 Byte
        session_key = os.urandom(8)
        print(f"[A] Session Key dibuat (hex): {session_key.hex()}")

        # 3. ENKRIPSI KUNCI (Confidentiality) -> Pakai Public Key Server
        # Agar hanya server yang bisa baca kunci ini.
        key_parts = []
        for byte in session_key:
            key_parts.append(byte >> 4)   # High nibble
            key_parts.append(byte & 0x0F) # Low nibble
        
        # Enkripsi setiap nibble: C = M^e mod n (Server)
        encrypted_parts = [pow(m, server_e, server_n) for m in key_parts]

        # 4. BUAT SIGNATURE (Authentication) -> Pakai Private Key Client
        # Agar server yakin kunci ini dari kita.
        # a. Buat Hash sederhana dari Session Key (Sum mod n)
        data_hash = sum(session_key) % CLIENT_N
        print(f"[A] Hash Session Key: {data_hash}")

        # b. Sign Hash: S = Hash^d mod n (Client)
        # Sesuai materi: "private-key... used to sign"
        signature = pow(data_hash, CLIENT_D, CLIENT_N)
        print(f"[A] Signature dibuat: {signature}")

        # 5. Kirim Paket Lengkap ke Hub
        packet = {
            "key_parts": encrypted_parts, # Kunci terenkripsi
            "signature": signature,       # Tanda tangan digital
            "client_n": CLIENT_N,         # Public Key kita (agar server bisa verifikasi)
            "client_e": CLIENT_E
        }
        send_json_line(sock, packet)
        print("[A] Kunci Terenkripsi + Signature telah dikirim.")

        # 6. Tunggu Konfirmasi (ACK) dari Server
        ack = recv_json_line(sock)
        if ack and ack.get("status") == "KEY_OK":
            des_cipher = DESFromScratch(session_key)
            print("[A] Key Exchange SUKSES & Terverifikasi.")
            return True
        else:
            err = ack.get("error", "Unknown") if ack else "No response"
            print(f"[A] Gagal: Server menolak kunci. Error: {err}")
            return False

    except Exception as e:
        print(f"[A] Error saat Key Exchange: {e}")
        return False

# --- THREAD PENERIMA PESAN (SAMA SEPERTI SEBELUMNYA) ---
def receive_messages(sock):
    global des_cipher
    print("[A] Thread penerima pesan dimulai.")
    try:
        while True:
            resp = recv_json_line(sock)
            if resp is None:
                print("\n[A] Koneksi terputus dari Server.")
                break 
            
            msg_type = resp.get("type")
            
            if msg_type == "cipher_from_B":
                # Terima pesan terenkripsi dari partner -> Dekripsi
                hex_ct = resp["hex"]
                decrypted_payload = des_cipher.decrypt(bytes.fromhex(hex_ct))
                try:
                    packet = json.loads(decrypted_payload)
                    print(f"\n[Pesan Masuk]: {packet['msg']}")
                except:
                    print(f"\n[Pesan Masuk]: {decrypted_payload} (Format raw)")
                
                print("[A] Ketik pesan: ", end="", flush=True)
            
            elif msg_type == "info":
                # Info sistem dari server
                print(f"\n[SERVER]: {resp.get('msg')}")
                print("[A] Ketik pesan: ", end="", flush=True)

    except Exception as e:
        print(f"\n[A] Error thread penerima: {e}")
    finally:
        sock.close()
        os._exit(0) # Matikan program jika koneksi putus

# --- FUNGSI UTAMA (MAIN LOOP) ---
def main():
    global des_cipher
    print(f"[A] Client Chat Siap.")
    
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        print(f"[A] Menghubungkan ke {SERVER_IP}:{SERVER_PORT} ...")
        sock.connect((SERVER_IP, SERVER_PORT))
    except Exception as e:
        print(f"[A] GAGAL terhubung: {e}")
        return

    # 1. Lakukan Authenticated Key Exchange
    if not perform_authenticated_key_exchange(sock):
        print("[A] Handshake gagal. Keluar.")
        sock.close()
        return

    # 2. Mulai Thread Penerima
    recv_thread = threading.Thread(target=receive_messages, args=(sock,))
    recv_thread.daemon = True 
    recv_thread.start()
    
    # 3. Loop Pengirim Pesan (Main Thread)
    try:
        time.sleep(0.5) # Jeda sedikit agar tampilan rapi
        print("\n=== MULAI CHATTING (Ketik 'exit' untuk keluar) ===")
        print("[A] Ketik pesan: ", end="", flush=True)
        
        while True:
            msg = input()
            
            if msg.lower() == "exit":
                break
            if not msg:
                print("[A] Ketik pesan: ", end="", flush=True)
                continue

            # Buat paket JSON berisi pesan & timestamp
            packet_to_encrypt = {
                "msg": msg,
                "ts": int(time.time()) 
            }
            plaintext_json = json.dumps(packet_to_encrypt)

            # Enkripsi menggunakan Session Key DES
            ct = des_cipher.encrypt(plaintext_json)
            
            # Kirim ke Server
            send_json_line(sock, {
                "type": "cipher_from_A",
                "hex": ct.hex()
            })
            
            # Tampilkan prompt lagi (kosmetik)
            print("[A] Ketik pesan: ", end="", flush=True)

    except KeyboardInterrupt:
        print("\n[A] Keluar...")
    except Exception as e:
        print(f"\n[A] Error pengirim: {e}")
    finally:
        sock.close()
        print("[A] Koneksi ditutup.")

if __name__ == "__main__":
    main()