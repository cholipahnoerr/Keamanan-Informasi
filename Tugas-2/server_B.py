# server_B.py
import socket, json, sys
from pathlib import Path

# Import kelas DES kamu
# Pastikan des_scratch.py ada di folder yang sama atau beri path absolut.
from des_scratch import DESFromScratch

HOST = "0.0.0.0"
PORT = 5000

# Ganti dengan 8-char key kamu (DES = 8 byte)
KEY_A_TO_B = b"KEYAB__1"  # pesan dari A -> B didekrip oleh B dengan kunci ini
KEY_B_TO_A = b"KEYBA__2"  # balasan dari B -> A dienkrip oleh B dengan kunci ini

des_from_A = DESFromScratch(KEY_A_TO_B)
des_to_A   = DESFromScratch(KEY_B_TO_A)

def recv_json_line(conn):
    buf = b""
    while b"\n" not in buf:
        chunk = conn.recv(4096)
        if not chunk:
            return None
        buf += chunk
    line, rest = buf.split(b"\n", 1)
    # sisakan sisa ke receive buffer sederhana (minimalis)
    # untuk kepraktisan contoh, abaikan rest
    return json.loads(line.decode("utf-8"))

def send_json_line(conn, obj):
    data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    conn.sendall(data)

def main():
    print(f"[B] Listening on {HOST}:{PORT}")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.bind((HOST, PORT))
        s.listen(1)
        conn, addr = s.accept()
        with conn:
            print(f"[B] Connected from {addr}")
            while True:
                incoming = recv_json_line(conn)
                if incoming is None:
                    print("[B] Client disconnected.")
                    break

                if incoming.get("type") != "cipher_from_A":
                    send_json_line(conn, {"type":"error","msg":"invalid message type"})
                    continue

                hex_ct = incoming.get("hex")
                try:
                    pt = des_from_A.decrypt(bytes.fromhex(hex_ct))
                except Exception as e:
                    send_json_line(conn, {"type":"error","msg":f"decrypt failed: {e}"})
                    continue

                print(f"[B] Pesan dari A (dekrip): {pt}")

                reply = input("[B] Ketik balasan ke A (plain): ")
                ct_reply = des_to_A.encrypt(reply)
                send_json_line(conn, {
                    "type":"cipher_from_B",
                    "hex": ct_reply.hex()
                })

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[B] Bye.")
