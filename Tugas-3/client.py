# (Device 2 - Bertindak sebagai Client "A" yang Menghubungi)
import socket, json, sys, time
from des_scratch import DESFromScratch # Mengimpor modul DES yang kita buat

# --- TAMBAHKAN IMPOR 'os' DAN 'threading' ---
import os 
import threading
# ---------------------------------------------

# --- KONFIGURASI CLIENT ---
SERVER_IP = input("Masukkan IP Server (Device 1): ") 
SERVER_PORT = 5000

# Objek 'des_cipher' akan dibuat SETELAH key exchange
des_cipher = None
    
# --- FUNGSI UTILITAS JARINGAN (JSON) ---
# (Fungsi recv_json_line dan send_json_line SAMA PERSIS)
def recv_json_line(sock):
    buf = b""
    while b"\n" not in buf:
        try:
            chunk = sock.recv(4096)
            if not chunk:
                return None
            buf += chunk
        except ConnectionResetError:
            return None
    line, rest = buf.split(b"\n", 1)
    return json.loads(line.decode("utf-8"))

def send_json_line(sock, obj):
    try:
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        sock.sendall(data)
    except (ConnectionResetError, BrokenPipeError):
        pass # Koneksi sudah mati, tidak apa-apa

# --- FUNGSI KEY EXCHANGE (SAMA PERSIS) ---
def perform_key_exchange(sock):
    global des_cipher
    try:
        incoming = recv_json_line(sock)
        if not incoming or "n" not in incoming or "e" not in incoming:
            raise ConnectionError("Gagal menerima public key dari server.")
        
        rsa_n = incoming["n"]
        rsa_e = incoming["e"]
        print(f"[A] Kunci publik server diterima: n={rsa_n}, e={rsa_e}")

        session_key = os.urandom(8) 
        print(f"[A] Session key DES di-generate (hex): {session_key.hex()}")

        key_parts_to_encrypt = []
        for byte in session_key: 
            high_nibble = byte >> 4    
            low_nibble = byte & 0x0F 
            key_parts_to_encrypt.append(high_nibble)
            key_parts_to_encrypt.append(low_nibble)
            
        print(f"[A] Kunci dipecah menjadi 16 nibble: {key_parts_to_encrypt}")

        encrypted_key_parts = []
        for part in key_parts_to_encrypt: 
            c = pow(part, rsa_e, rsa_n)
            encrypted_key_parts.append(c)

        print(f"[A] 16 bagian kunci terenkripsi: {encrypted_key_parts}")

        send_json_line(sock, {"key_parts": encrypted_key_parts})
        print("[A] Session key terenkripsi telah dikirim ke server.")

        ack = recv_json_line(sock)
        if not ack or ack.get("status") != "KEY_OK":
            raise ConnectionError(f"Gagal menerima ACK kunci. Server: {ack.get('error', 'Unknown error')}")
        
        des_cipher = DESFromScratch(session_key)
        print("[A] Objek DES diinisialisasi. Komunikasi aman siap.")
        return True

    except Exception as e:
        print(f"[A] ERROR saat Key Exchange: {e}")
        return False

# --- LOGIKA PENERIMA PESAN (BARU) ---
def receive_messages(sock):
    """Fungsi thread untuk Menerima & Mendekripsi pesan."""
    global des_cipher
    print("[A] Thread penerima pesan dimulai.")
    try:
        while True:
            resp = recv_json_line(sock)
            if resp is None:
                print("\n[A] Server menutup koneksi. Tekan Enter untuk keluar.")
                break # Keluar dari loop jika server disconnect
            
            msg_type = resp.get("type")
            
            if msg_type == "cipher_from_B":
                # Ini adalah balasan chat dari partner
                hex_ct = resp["hex"]
                decrypted_payload = des_cipher.decrypt(bytes.fromhex(hex_ct))
                reply_packet = json.loads(decrypted_payload)
                print(f"\n[Pesan dari Partner]: {reply_packet['msg']}")
                print("[A] Ketik pesan (plain): ", end="", flush=True) # Minta input lagi
            
            elif msg_type == "info":
                # Ini pesan info dari server (seperti "CONNECTED" atau "disconnect")
                print(f"\n[SERVER INFO]: {resp.get('msg')}")
                print("[A] Ketik pesan (plain): ", end="", flush=True) # Minta input lagi
            
            else:
                # Ini adalah pesan yang tidak kita duga
                print(f"\n[A] Respon tidak dikenal: {resp}")
                print("[A] Ketik pesan (plain): ", end="", flush=True)

    except (ConnectionResetError, BrokenPipeError):
        print("\n[A] Koneksi terputus (server mungkin crash/berhenti). Tekan Enter untuk keluar.")
    except Exception as e:
        # Menangani error jika kunci salah (padding/json)
        print(f"\n[A] Error di thread penerima (mungkin data korup/kunci salah): {e}. Tekan Enter untuk keluar.")
    finally:
        sock.close() # Pastikan socket ditutup jika thread mati

# --- FUNGSI UTAMA CLIENT (DIMODIFIKASI) ---
def main():
    global des_cipher
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
        # 1. LAKUKAN KEY EXCHANGE
        if not perform_key_exchange(sock):
            print("[A] Key exchange gagal. Menutup koneksi.")
            return

        # 2. MULAI THREAD PENERIMA PESAN
        # Thread ini akan berjalan di background, hanya untuk menerima
        recv_thread = threading.Thread(target=receive_messages, args=(sock,))
        recv_thread.daemon = True # Agar thread mati saat program utama ditutup
        recv_thread.start()
        
        # 3. LOOP PENGIRIM PESAN (DI MAIN THREAD)
        # Loop ini hanya untuk mengirim
        try:
            # Beri jeda 1 detik agar pesan "CONNECTED" dari server masuk lebih dulu
            time.sleep(1) 
            
            while True:
                msg = input("[A] Ketik pesan (plain): ")
                
                # Cek apakah thread penerima masih hidup. Jika tidak, hentikan input.
                if not recv_thread.is_alive():
                    print("[A] Koneksi penerima mati. Program akan berhenti.")
                    break
                
                if msg == "": # Izinkan mengirim pesan kosong, tapi 'exit' untuk keluar
                    continue
                if msg.lower() == "exit":
                    break

                current_time = int(time.time())
                packet_to_encrypt = {
                    "msg": msg,
                    "ts": current_time 
                }
                plaintext_json = json.dumps(packet_to_encrypt)

                ct = des_cipher.encrypt(plaintext_json)
                
                # Kirim pesan (tanpa menunggu balasan di sini)
                send_json_line(sock, {
                    "type": "cipher_from_A",
                    "hex": ct.hex()
                })

        except (KeyboardInterrupt, EOFError):
            print("\n[A] Keluar...")
        except Exception as e:
            print(f"\n[A] Error di thread pengirim: {e}")
        finally:
            sock.close()
            print("[A] Koneksi ditutup.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[A] Keluar.")
