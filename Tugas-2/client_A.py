# client_A.py
import socket, json, sys
from des_scratch import DESFromScratch

# IP device B dan port harus benar
SERVER_IP = "127.0.0.1"   # ganti ke IP device B di jaringanmu
SERVER_PORT = 5000

# 8-char key, harus sama definisinya dengan yang dipakai B
KEY_A_TO_B = b"KEYAB__1"  # untuk enkripsi pesan dari A -> B
KEY_B_TO_A = b"KEYBA__2"  # untuk dekripsi balasan dari B -> A

des_to_B   = DESFromScratch(KEY_A_TO_B)
des_from_B = DESFromScratch(KEY_B_TO_A)

def recv_json_line(sock):
    buf = b""
    while b"\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            return None
        buf += chunk
    line, rest = buf.split(b"\n", 1)
    return json.loads(line.decode("utf-8"))

def send_json_line(sock, obj):
    data = (json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8")
    sock.sendall(data)

def main():
    print(f"[A] Connecting to {SERVER_IP}:{SERVER_PORT} ...")
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.connect((SERVER_IP, SERVER_PORT))
        print("[A] Connected.")

        while True:
            msg = input("[A] Ketik pesan ke B (plain, kosong untuk keluar): ")
            if msg == "":
                break

            ct = des_to_B.encrypt(msg)
            send_json_line(sock, {
                "type":"cipher_from_A",
                "hex": ct.hex()
            })

            resp = recv_json_line(sock)
            if resp is None:
                print("[A] Server closed connection.")
                break
            if resp.get("type") != "cipher_from_B":
                print("[A] Invalid response:", resp)
                continue

            try:
                pt_reply = des_from_B.decrypt(bytes.fromhex(resp["hex"]))
                print(f"[A] Balasan dari B (dekrip): {pt_reply}")
            except Exception as e:
                print(f"[A] Gagal dekripsi balasan: {e}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[A] Bye.")
