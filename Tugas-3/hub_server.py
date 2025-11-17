# (Server "Hub" - Menjembatani dua client)
import socket, json, sys, time
import threading # Kita WAJIB menggunakan threading
from des_scratch import DESFromScratch 

# --- KONFIGURASI SERVER ---
HOST = "0.0.0.0"
PORT = 5000
TIMESTAMP_WINDOW = 10 

# --- KUNCI RSA DARI CONTOH KULIAH (KI 12.pdf, hal 20) ---
RSA_N = 187  # Modulus (n)
RSA_E = 7    # Public Exponent (e)
RSA_D = 23   # Private Exponent (d)
# --------------------------------------------------------

# --- FUNGSI UTILITAS JARINGAN (JSON) ---
# (Fungsi recv_json_line dan send_json_line SAMA PERSIS)
def recv_json_line(conn):
    buf = b""
    while b"\n" not in buf:
        try:
            chunk = conn.recv(4096)
            if not chunk: 
                return None
            buf += chunk
        except ConnectionResetError:
            return None
    line, rest = buf.split(b"\n", 1) 
    return json.loads(line.decode("utf-8"))

def send_json_line(conn, obj):
    try:
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        conn.sendall(data)
    except (ConnectionResetError, BrokenPipeError):
        pass # Client sudah disconnect, tidak apa-apa

# --- FUNGSI KEY EXCHANGE (Hampir sama, tapi me-return cipher) ---
def perform_key_exchange(conn, client_name):
    """Melakukan key exchange, mengembalikan objek DES yang sudah jadi."""
    try:
        # 1: Kirim Kunci Publik (PU={e,n})
        public_key_data = {"n": RSA_N, "e": RSA_E}
        send_json_line(conn, public_key_data)
        print(f"[HUB] Kunci publik RSA dikirim ke {client_name}.")

        # 2: Terima Kunci DES terenkripsi (16 bagian)
        incoming = recv_json_line(conn)
        if not incoming or "key_parts" not in incoming:
            raise ConnectionError(f"{client_name} terputus/gagal mengirim session key.")

        encrypted_key_parts = incoming["key_parts"]
        if len(encrypted_key_parts) != 16:
            raise ValueError(f"Session key {client_name} bukan 16 bagian.")
        
        # 3: Dekripsi 16 bagian kunci
        decrypted_nibbles = [pow(c, RSA_D, RSA_N) for c in encrypted_key_parts]
        
        # 4: Rekonstruksi 8 byte dari 16 nibble
        session_key_bytes = []
        for i in range(0, 16, 2):
            byte_val = (decrypted_nibbles[i] << 4) | decrypted_nibbles[i+1] 
            session_key_bytes.append(byte_val)
            
        session_key = bytes(session_key_bytes)
        print(f"[HUB] Session key {client_name} didekripsi (hex): {session_key.hex()}")

        # 5: Inisialisasi DES Cipher
        des_cipher = DESFromScratch(session_key)
        print(f"[HUB] Objek DES untuk {client_name} diinisialisasi.")
        
        # 6: Kirim ACK
        send_json_line(conn, {"status": "KEY_OK"})
        return des_cipher # Kembalikan objek cipher yang sudah jadi

    except Exception as e:
        print(f"[HUB] ERROR saat Key Exchange dengan {client_name}: {e}")
        send_json_line(conn, {"status": "KEY_FAIL", "error": str(e)})
        return None

# --- FUNGSI RELAY (INTI LOGIKA BARU) ---
def relay_messages(name_from, conn_from, cipher_from, 
                   name_to,   conn_to,   cipher_to):
    """
    Satu thread. Terus-menerus menerima dari 'from', dekrip,
    enkrip ulang, dan kirim ke 'to'.
    """
    print(f"[THREAD] Memulai relay dari {name_from} ke {name_to}...")
    try:
        while True:
            # 1. Menerima dari 'from'
            incoming = recv_json_line(conn_from)
            if incoming is None:
                print(f"[HUB] {name_from} telah disconnect.")
                send_json_line(conn_to, {"type": "info", "msg": f"{name_from} has disconnected."})
                break
            
            if incoming.get("type") != "cipher_from_A": # Client masih mengirim 'cipher_from_A'
                print(f"[HUB] WARNING: Tipe pesan tidak valid dari {name_from}.")
                continue

            # 2. Dekripsi (menggunakan kunci 'from')
            hex_ct = incoming["hex"]
            decrypted_payload = cipher_from.decrypt(bytes.fromhex(hex_ct))
            packet = json.loads(decrypted_payload)

            # 3. Validasi Timestamp
            server_time = int(time.time())
            client_time = packet.get("ts")
            if abs(server_time - client_time) > TIMESTAMP_WINDOW:
                print(f"[HUB] REJECT: Replay attack terdeteksi dari {name_from}. Pesan dibuang.")
                continue
            
            # 4. Tampilkan pesan di Server Hub
            pt_msg = packet.get("msg")
            print(f"\n[Relay: {name_from} -> {name_to}]: {pt_msg}")

            # 5. Siapkan & Enkripsi Ulang (menggunakan kunci 'to')
            reply_packet_to_encrypt = {
                "msg": pt_msg, # Kirim pesan aslinya
                "ts": int(time.time()) # Buat timestamp baru
            }
            plaintext_json_reply = json.dumps(reply_packet_to_encrypt)
            
            # Enkripsi dengan kunci TUJUAN
            ct_reply = cipher_to.encrypt(plaintext_json_reply)

            # 6. Kirim ke 'to'
            send_json_line(conn_to, {
                "type":"cipher_from_B", # Client masih mengharapkan 'cipher_from_B'
                "hex": ct_reply.hex()
            })

    except (ValueError, TypeError, json.JSONDecodeError):
        print(f"[HUB] ERROR: Kunci salah/data korup dari {name_from}. Menutup thread.")
    except Exception as e:
        print(f"[HUB] ERROR di thread {name_from}: {e}")
    finally:
        print(f"[HUB] Menutup koneksi untuk {name_from}.")
        conn_from.close()
        # Beri tahu client lain bahwa koneksi ini mati
        try:
            send_json_line(conn_to, {"type": "info", "msg": f"{name_from} has disconnected."})
        except:
            pass # Client 'to' mungkin sudah mati juga

# --- FUNGSI UTAMA SERVER ---
def main():
    print(f"[HUB] Server Chat (Device 1) siap.")
    print(f"[HUB] Kunci RSA di-load: n={RSA_N}, e={RSA_E}, d={RSA_D}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(2) # Siap menerima 2 koneksi
        print(f"[HUB] Mendengarkan di {HOST}:{PORT}")

        # 1. Terima Client 1
        print("[HUB] Menunggu Client 1...")
        conn1, addr1 = s.accept()
        print(f"[HUB] Client 1 terhubung: {addr1}")
        
        # 2. Terima Client 2
        print("[HUB] Menunggu Client 2...")
        conn2, addr2 = s.accept()
        print(f"[HUB] Client 2 terhubung: {addr2}")
        
        # 3. Lakukan Key Exchange dengan KEDUA client
        des_cipher_1 = perform_key_exchange(conn1, "Client 1")
        des_cipher_2 = perform_key_exchange(conn2, "Client 2")
        
        if not des_cipher_1 or not des_cipher_2:
            print("[HUB] Key exchange gagal. Menutup server.")
            conn1.close()
            conn2.close()
            return
            
        print("\n[HUB] Key exchange sukses. Kedua client terhubung. Relay dimulai.")
        send_json_line(conn1, {"type": "info", "msg": "CONNECTED: You are Client 1."})
        send_json_line(conn2, {"type": "info", "msg": "CONNECTED: You are Client 2."})

        # 4. Buat 2 Thread Relay
        # Thread 1: Menerima dari C1, mengirim ke C2
        t1 = threading.Thread(target=relay_messages, 
                              args=("Client 1", conn1, des_cipher_1, 
                                    "Client 2", conn2, des_cipher_2))
        
        # Thread 2: Menerima dari C2, mengirim ke C1
        t2 = threading.Thread(target=relay_messages, 
                              args=("Client 2", conn2, des_cipher_2, 
                                    "Client 1", conn1, des_cipher_1))

        t1.start()
        t2.start()
        
        t1.join() # Tunggu thread 1 selesai
        t2.join() # Tunggu thread 2 selesai
        
        print("[HUB] Kedua client telah disconnect. Server shutdown.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[HUB] Server dihentikan.")
