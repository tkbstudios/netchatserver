import socket
import threading
import requests
import logging
from colorlog import ColoredFormatter

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = ColoredFormatter(
    "%(log_color)s%(levelname)-8s%(reset)s %(cyan)s%(message)s",
    datefmt=None,
    reset=True,
    log_colors={
        'DEBUG':    'cyan',
        'INFO':     'green',
        'WARNING':  'yellow',
        'ERROR':    'red',
        'CRITICAL': 'red,bg_white',
    },
    secondary_log_colors={},
    style='%'
)

console_handler = logging.StreamHandler()
console_handler.setFormatter(formatter)
logger.addHandler(console_handler)

TINET_BASE_API_URL = "https://tinet.tkbstudios.com/api"

sessions = {}


def get_session_token(username, calc_key):
    get_session_url = f"{TINET_BASE_API_URL}/v1/user/calc/auth"
    headers = {
        "Content-Type": 'application/json',
        "Accept": 'application/json'
    }
    body = {
        "username": username,
        "calc_key": calc_key
    }
    session_token_request = requests.post(get_session_url, headers=headers, json=body)
    if session_token_request.status_code == 200:
        session_token_request_json = session_token_request.json()
        if session_token_request_json['auth_success'] is True:
            session_token = session_token_request_json['session_token']
            sessions[username] = session_token
            return session_token
        else:
            return False
    return None


def get_user_data_from_api(username):
    session_token = sessions.get(username)
    if session_token:
        auth_with_session_token_url = f"{TINET_BASE_API_URL}/v1/user/sessions/auth"
        headers = {
            "Content-Type": 'application/json',
            "Accept": 'application/json'
        }
        body = {
            "username": username,
            "session_token": session_token
        }
        session_token_request = requests.post(auth_with_session_token_url, headers=headers, json=body)
        if session_token_request.status_code == 200:
            user_data = session_token_request.json()
            return user_data
    return None


# TODO: make sending messages work
# TODO: add rate limiting
def handle_client(client_socket, client_address, clients):
    logger.debug(f"Accepted connection from {client_address}")

    authenticated = False
    username = None
    userdata = None

    while True:
        try:
            data = client_socket.recv(2048)
            if not data:
                break

            message = data.decode().strip()

            if not authenticated:
                if message.startswith("AUTH:"):
                    parts = message.split(":")
                    if len(parts) == 3:
                        _, received_username, received_calc_key = parts

                        session_token = get_session_token(received_username, received_calc_key)

                        if session_token:
                            userdata = get_user_data_from_api(received_username)
                            if userdata:
                                authenticated = True
                                username = received_username
                                client_socket.sendall(b"AUTH_SUCCESS")
                                logger.debug(f"User {username} authenticated successfully. User data: {userdata}")
                            else:
                                client_socket.sendall(b"AUTH_FAILED:Could not get user data from TINET")
                        else:
                            client_socket.sendall(b"AUTH_FAILED:Could not fetch a session token from TINET")
                            logger.warning(f"Authentication failed for user {received_username}.")
                    else:
                        client_socket.sendall(b"ERROR:Invalid message format")
                else:
                    client_socket.sendall(b"AUTH_REQUIRED")
            else:
                if ":" in message:
                    recipient, msg = message.split(":", 1)
                    recipient = recipient.strip()
                    msg = msg.strip()
                    for c in clients:
                        if c != client_socket:
                            if c.getpeername()[0] == recipient and c.getpeername()[0] in sessions:
                                c.sendall(f"{username}: {msg}".encode())
                                break
                    else:
                        client_socket.sendall(b"ERROR:Recipient not found or not authenticated")
                else:
                    client_socket.sendall(b"ERROR:Invalid message format")
        except Exception as e:
            logger.error(f"Error: {e}")
            break

    clients.remove(client_socket)
    client_socket.close()
    logger.debug(f"Connection from {client_address} closed")


def main():
    host = '0.0.0.0'
    port = 2052
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind((host, port))
    server_socket.listen(5)
    logger.info(f"Server listening on {host}:{port}")

    clients = []

    try:
        while True:
            client_socket, client_address = server_socket.accept()
            clients.append(client_socket)
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address, clients))
            client_thread.start()
    except KeyboardInterrupt:
        logger.info("Shutting down the server.")
        for client_socket in clients:
            client_socket.close()
        server_socket.close()


if __name__ == "__main__":
    main()
