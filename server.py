import socket
import threading


def handle_client(client_socket, client_address, clients):
    print(f"Accepted connection from {client_address}")

    while True:
        try:
            data = client_socket.recv(1024)
            if not data:
                break

            for c in clients:
                if c != client_socket:
                    c.sendall(data)
        except Exception as e:
            print(f"Error: {e}")
            break

    clients.remove(client_socket)
    client_socket.close()
    print(f"Connection from {client_address} closed")


def main():
    host = '0.0.0.0'
    port = 9999
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    print(f"Server listening on {host}:{port}")

    clients = []

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            clients.append(client_socket)
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address, clients))
            client_thread.start()
    except KeyboardInterrupt:
        print("Shutting down the server.")
        for client_socket in clients:
            client_socket.close()
        server_socket.close()


if __name__ == "__main__":
    main()
