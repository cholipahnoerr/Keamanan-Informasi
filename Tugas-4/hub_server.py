# hub_server.py
# (Server "Hub" - Menjembatani dua client dengan Autentikasi Signature)
import socket, json, sys, time
import threading 
from des_scratch import DESFromScratch 

# --- KONFIGURASI SERVER ---
HOST = "0.0.0.0"
PORT = 5000
TIMESTAMP_WINDOW = 10 

# --- KUNCI RSA HUB (Sama seperti Server B sebelumnya) ---
RSA_N = 187  # Modulus
RSA_E = 7    # Public Exponent
RSA_D = 23   # Private Exponent
# --------------------------------------------------------

# --- FUNGSI UTILITAS JARINGAN (JSON) ---
def recv_json_line(conn):
    buf = b""
    while b"\n" not in buf:
        try:
            chunk = conn.recv(4096)
            if not chunk: return None
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
        pass 

# --- FUNGSI KEY EXCHANGE DENGAN VERIFIKASI (BARU) ---
def perform_authenticated_key_exchange(conn, client_name):
    """
    Melakukan key exchange, memverifikasi signature client,
    dan mengembalikan objek DES yang sudah jadi.
    """
    try:
        # 1. Kirim Kunci Publik Hub (PU={e,n}) ke Client
        public_key_data = {"n": RSA_N, "e": RSA_E}
        send_json_line(conn, public_key_data)
        print(f"[HUB] Kunci publik RSA dikirim ke {client_name}.")

        # 2. Terima Paket Kunci & Signature dari Client
        incoming = recv_json_line(conn)
        if not incoming:
            raise ConnectionError(f"{client_name} terputus saat handshake.")
        
        # Pastikan semua komponen ada
        if not all(k in incoming for k in ("key_parts", "signature", "client_n", "client_e")):
             raise ValueError(f"Format data dari {client_name} tidak valid/lama.")

        encrypted_parts = incoming["key_parts"]
        signature = incoming["signature"]
        client_n = incoming["client_n"]
        client_e = incoming["client_e"]

        print(f"[HUB] Menerima data terenkripsi + Signature dari {client_name}.")
        
        # 3. DEKRIPSI Session Key (Confidentiality)
        # Gunakan Private Key Hub (RSA_D)
        decrypted_nibbles = [pow(c, RSA_D, RSA_N) for c in encrypted_parts]
        
        session_key_bytes = []
        for i in range(0, 16, 2):
            byte_val = (decrypted_nibbles[i] << 4) | decrypted_nibbles[i+1] 
            session_key_bytes.append(byte_val)
        session_key = bytes(session_key_bytes)
        print(f"[HUB] Session key {client_name} didekripsi.")

        # 4. VERIFIKASI SIGNATURE (Authentication)
        # a. Hitung hash dari session key yang diterima
        calculated_hash = sum(session_key) % client_n
        
        # b. Verifikasi signature menggunakan Public Key Client yang dikirim
        #    H' = S^e mod n (Client)
        verified_hash = pow(signature, client_e, client_n)

        if calculated_hash != verified_hash:
            raise ValueError(f"SIGNATURE INVALID dari {client_name}! Autentikasi gagal.")
        
        print(f"[HUB] Signature {client_name} VALID. Identitas terverifikasi.")

        # 5. Inisialisasi DES Cipher
        des_cipher = DESFromScratch(session_key)
        
        # 6. Kirim ACK
        send_json_line(conn, {"status": "KEY_OK"})
        return des_cipher 

    except Exception as e:
        print(f"[HUB] ERROR Key Exchange dengan {client_name}: {e}")
        try:
            send_json_line(conn, {"status": "KEY_FAIL", "error": str(e)})
        except: pass
        return None

# --- FUNGSI RELAY (TIDAK BERUBAH) ---
def relay_messages(name_from, conn_from, cipher_from, 
                   name_to,   conn_to,   cipher_to):
    """Relay pesan antar client (Dekrip dari A -> Enkrip untuk B)."""
    print(f"[THREAD] Memulai relay dari {name_from} ke {name_to}...")
    try:
        while True:
            # 1. Terima
            incoming = recv_json_line(conn_from)
            if incoming is None:
                print(f"[HUB] {name_from} disconnect.")
                send_json_line(conn_to, {"type": "info", "msg": f"{name_from} has disconnected."})
                break
            
            if incoming.get("type") != "cipher_from_A": 
                continue

            # 2. Dekripsi (Kunci 'From')
            hex_ct = incoming["hex"]
            decrypted_payload = cipher_from.decrypt(bytes.fromhex(hex_ct))
            packet = json.loads(decrypted_payload)

            # 3. Cek Timestamp
            server_time = int(time.time())
            if abs(server_time - packet.get("ts")) > TIMESTAMP_WINDOW:
                print(f"[HUB] REJECT: Replay attack dari {name_from}.")
                continue
            
            pt_msg = packet.get("msg")
            print(f"\n[Relay: {name_from} -> {name_to}]: {pt_msg}")

            # 4. Enkripsi Ulang (Kunci 'To')
            reply_packet = {"msg": pt_msg, "ts": int(time.time())}
            ct_reply = cipher_to.encrypt(json.dumps(reply_packet))

            # 5. Kirim
            send_json_line(conn_to, {
                "type":"cipher_from_B", 
                "hex": ct_reply.hex()
            })

    except Exception as e:
        print(f"[HUB] ERROR Relay {name_from}: {e}")
    finally:
        conn_from.close()

# --- FUNGSI UTAMA SERVER ---
def main():
    print(f"[HUB] Server Chat (Device 1) siap.")
    print(f"[HUB] Kunci RSA Hub: n={RSA_N}, e={RSA_E}, d={RSA_D}")
    
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(2) 
        print(f"[HUB] Mendengarkan di {HOST}:{PORT}")

        # 1. Terima Client 1
        print("[HUB] Menunggu Client 1...")
        conn1, addr1 = s.accept()
        print(f"[HUB] Client 1 terhubung: {addr1}")
        
        # 2. Terima Client 2
        print("[HUB] Menunggu Client 2...")
        conn2, addr2 = s.accept()
        print(f"[HUB] Client 2 terhubung: {addr2}")
        
        # 3. Lakukan Authenticated Key Exchange dengan KEDUA client
        #    Hub bertindak sebagai "Server" untuk keduanya
        des_cipher_1 = perform_authenticated_key_exchange(conn1, "Client 1")
        des_cipher_2 = perform_authenticated_key_exchange(conn2, "Client 2")
        
        if not des_cipher_1 or not des_cipher_2:
            print("[HUB] Key exchange gagal. Menutup server.")
            conn1.close()
            conn2.close()
            return
            
        print("\n[HUB] Kedua client terautentikasi & terhubung. Relay dimulai.")
        send_json_line(conn1, {"type": "info", "msg": "CONNECTED: You are Client 1."})
        send_json_line(conn2, {"type": "info", "msg": "CONNECTED: You are Client 2."})

        # 4. Jalankan Thread Relay
        t1 = threading.Thread(target=relay_messages, 
                              args=("Client 1", conn1, des_cipher_1, 
                                    "Client 2", conn2, des_cipher_2))
        
        t2 = threading.Thread(target=relay_messages, 
                              args=("Client 2", conn2, des_cipher_2, 
                                    "Client 1", conn1, des_cipher_1))

        t1.start()
        t2.start()
        t1.join()
        t2.join()
        print("[HUB] Server shutdown.")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[HUB] Server dihentikan.")