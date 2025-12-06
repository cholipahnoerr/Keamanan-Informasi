# (Device 1 - Bertindak sebagai Server "B" yang Mendengarkan)

import socket
import json
import sys
import time
from des_scratch import DESFromScratch # Mengimpor modul DES yang kita buat

# --- KONFIGURASI SERVER ---
HOST = "0.0.0.0"       # Mendengarkan di semua interface (penting agar device lain bisa konek)
PORT = 5000            # Port yang akan didengarkan
KEY_A_TO_B = b"87654321" # Kunci untuk MENDEKRIPSI pesan dari Client A
KEY_B_TO_A = b"87654321" # Kunci untuk MENGENKRIPSI balasan ke Client A
TIMESTAMP_WINDOW = 10  # Jendela toleransi waktu (detik) untuk anti-replay attack

# --- INISIALISASI OBJEK DES ---
# Kita butuh 2 objek DES: satu untuk dekripsi, satu untuk enkripsi balasan.
try:
    # Objek ini disiapkan untuk dekripsi (menggunakan KEY_A_TO_B)
    des_from_A = DESFromScratch(KEY_A_TO_B)
    # Objek ini disiapkan untuk enkripsi (menggunakan KEY_B_TO_A)
    des_to_A = DESFromScratch(KEY_B_TO_A)
except Exception as e:
    print(f"[ERROR] Gagal menginisialisasi DES. Cek S_BOXES atau panjang kunci. Error: {e}")
    sys.exit(1)

# --- FUNGSI UTILITAS JARINGAN (JSON) ---

def recv_json_line(conn):
    """Menerima data socket hingga menemukan newline (\n) & parse sebagai JSON."""
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk: # Jika client putus koneksi
            return None
        buf += chunk
    line, rest = buf.split(b"\n", 1) # Pisahkan pesan
    return json.loads(line.decode("utf-8"))

def send_json_line(conn, obj):
    """Mengubah objek Python (dict) ke JSON, tambah newline (\n), & kirim."""
    try:
        data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
        conn.sendall(data)
    except Exception as e:
        print(f"[B] Gagal mengirim balasan: {e}")

# --- FUNGSI UTAMA SERVER ---

def main():
    print(f"[B] Server (Device 1) siap.")
    print(f"[B] Mendengarkan di {HOST}:{PORT}")
    
    # 1. SETUP SOCKET
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        # Opsi agar port bisa dipakai lagi meski server baru saja crash
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1) # Hanya izinkan 1 antrian koneksi
        
        # 2. MENERIMA KONEKSI
        # .accept() adalah BLOKING -> program akan berhenti di sini sampai ada client konek
        conn, addr = s.accept()
        
        with conn:
            print(f"[B] BERHASIL: Terhubung dengan client {addr}")
            
            # 3. LOOP CHATTING UTAMA
            while True:
                # Blok 'try' ini penting agar server tidak crash jika ada error
                try:
                    # 4. MENERIMA PESAN DARI CLIENT
                    # Menerima paket JSON (yang berisi ciphertext)
                    incoming = recv_json_line(conn)
                    if incoming is None:
                        print("[B] INFO: Client menutup koneksi.")
                        break # Keluar dari loop

                    # Cek protokol mini kita
                    if incoming.get("type") != "cipher_from_A":
                        print(f"[B] WARNING: Tipe pesan tidak valid.")
                        continue

                    hex_ct = incoming.get("hex")
                    if not hex_ct:
                        print("[B] WARNING: Pesan tidak memiliki 'hex' data.")
                        continue
                        
                    # 5. DEKRIPSI PAYLOAD
                    # Ini adalah titik rawan: Gagal jika kunci salah atau S-Box salah
                    decrypted_payload = des_from_A.decrypt(bytes.fromhex(hex_ct))
                    
                    # Parse string JSON hasil dekripsi
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

                    # --- PROSES BALASAN ---
                    
                    # 8. MEMBUAT BALASAN
                    reply = input("[B] Balasan Anda (plain): ")
                    
                    # 9. SIAPKAN & ENKRIPSI BALASAN
                    current_time = int(time.time())
                    reply_packet_to_encrypt = {
                        "msg": reply,
                        "ts": current_time # Balasan juga pakai timestamp
                    }
                    plaintext_json_reply = json.dumps(reply_packet_to_encrypt)

                    # Enkripsi balasan menggunakan kunci B->A
                    ct_reply = des_to_A.encrypt(plaintext_json_reply)

                    # Blok demo: Menampilkan plaintext & ciphertext sebelum dikirim
                    print(f"   [+] Plaintext (JSON): {plaintext_json_reply}")
                    print(f"   [+] Ciphertext (Hex): {ct_reply.hex().upper()}")

                    # 10. KIRIM BALASAN TERENKRIPSI
                    send_json_line(conn, {
                        "type":"cipher_from_B",
                        "hex": ct_reply.hex()
                    })
                    print("[B] Balasan terenkripsi terkirim.")

                # --- BLOK PENANGANAN ERROR ---
                # Jika terjadi error saat dekripsi (misal: kunci salah), server tidak crash
                except json.JSONDecodeError as e:
                    print(f"[B] ERROR: Kunci salah. Gagal parse JSON hasil dekripsi. Error: {e}")
                except (ValueError, TypeError) as e:
                    print(f"[B] ERROR: Kunci salah. Gagal dekripsi/padding. Error: {e}")
                except Exception as e:
                    print(f"[B] ERROR: Terjadi error tak terduga: {e}")
                    continue # Coba lanjut ke pesan berikutnya

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[B] Server dihentikan.")
    except Exception as e:
        print(f"[B] SERVER CRASHED (diluar loop): {e}")