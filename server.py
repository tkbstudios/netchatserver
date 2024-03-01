import os
import random
import socket
import string
import threading
import requests
import logging
from colorlog import ColoredFormatter
import time
import configparser
import dotenv

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

formatter = ColoredFormatter(
    "%(log_color)s%(levelname)-8s%(reset)s %(cyan)s%(message)s",
    datefmt=None,
    reset=True,
    log_colors={
        'DEBUG': 'cyan',
        'INFO': 'green',
        'WARNING': 'yellow',
        'ERROR': 'red',
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
user_last_message_time = {}

config = configparser.ConfigParser()
config.read('server.properties')

dotenv.load_dotenv('.env')
APP_API_KEY = os.environ.get("APP_API_KEY").strip()

SERVER_ONLINE = False


def get_user_data_from_api(username):
    session_token = sessions.get(username)
    if session_token:
        auth_with_session_token_url = f"{TINET_BASE_API_URL}/v1/user/sessions/auth"
        headers = {
            "Content-Type": 'application/json',
            "Accept": 'application/json',
            "Api-Key": APP_API_KEY
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


def check_rate_limit(username):
    last_message_time = user_last_message_time.get(username)
    if last_message_time is not None:
        elapsed_time = time.time() - last_message_time
        if elapsed_time < 1:
            time.sleep(1 - elapsed_time)


def handle_client(client_socket, client_address, clients):
    global SERVER_ONLINE
    logger.debug(f"Accepted connection from {client_address}")

    authenticated = False
    username = None

    while SERVER_ONLINE:
        try:
            data = client_socket.recv(2048)
            if not data:
                break

            message = data.decode().strip()

            if not authenticated:
                if message.startswith("AUTH:"):
                    parts = message.split(":")
                    if len(parts) == 3:
                        _, received_username, received_session_token = parts
                        session_token = received_session_token
                        if not config.getboolean('server', 'online-mode', fallback=True):
                            authenticated = True
                            username = received_username
                            session_token = ''.join(
                                random.choice(string.ascii_letters + string.digits) for _ in range(256)
                            )
                            sessions[received_username] = session_token
                            client_socket.sendall(b"AUTH_SUCCESS\n")
                        else:
                            if session_token:
                                username = received_username
                                sessions[received_username] = session_token
                                userdata = get_user_data_from_api(received_username)
                                if userdata:
                                    authenticated = True
                                    client_socket.sendall(b"AUTH_SUCCESS\n")
                                    logger.debug(f"User {username} authenticated successfully. User data: {userdata}")
                                else:
                                    client_socket.sendall(b"AUTH_FAILED:Could not get user data from TINET\n")
                            else:
                                sessions.pop(received_username)
                                client_socket.sendall(b"AUTH_FAILED:No valid session token\n")
                                logger.warning(f"Authentication failed for user {received_username}.")
                    else:
                        client_socket.sendall(b"ERROR:Invalid message format\n")
                else:
                    client_socket.sendall(b"AUTH_REQUIRED\n")
            else:
                if ":" in message:
                    recipient, msg = message.split(":", 1)
                    recipient = recipient.strip()
                    msg = msg.strip()
                    if len(recipient) < 3:
                        client_socket.sendall(
                            b"ERROR:Invalid message format (recipient must be at least 3 characters)\n"
                        )
                        return

                    if recipient.lower() == "global":
                        check_rate_limit(username)
                        user_last_message_time[username] = time.time()
                        for client in clients:
                            client.sendall(f"{recipient}:{username}:{msg}\n".encode())
                            logger.debug(f"{username} sent `{msg}` to all clients in global lobby.")
                            if config.getboolean('discord', 'hook-enabled', fallback=False):
                                hook_url = config.get('discord', 'hook-url', fallback=None)
                                if hook_url:
                                    body = {
                                        "content": "",
                                        "embeds": [
                                            {
                                                "title": "New Message",
                                                "description": msg,
                                                "color": 65280,
                                                "author": {
                                                    "name": username
                                                },
                                                "footer": {
                                                    "text": "Sent from NETCHAT Server"
                                                }
                                            }
                                        ]
                                    }
                                    hook_post_request = requests.post(hook_url, json=body)
                                    if hook_post_request.status_code == 202:
                                        logger.debug(f"{username} sent `{msg}` to discord hook.")

                    else:
                        client_socket.sendall(b"ERROR:Please use the `global` recipient for now\n")
                else:
                    client_socket.sendall(b"ERROR:Invalid message format\n")
        except Exception as e:
            logger.error(f"Error: {e}")
            break

    clients.remove(client_socket)
    client_socket.close()
    if username and username in sessions:
        sessions.pop(username)
    logger.debug(f"Connection from {client_address} closed")


def main():
    global SERVER_ONLINE

    # load and check settings
    if not config.getboolean('server', 'online-mode', fallback=True):
        logger.warning("⚠️ " + "=" * 53)
        logger.warning("⚠️ = WARNING: This server is running in offline/insecure mode! =")
        logger.warning("⚠️ = This will not check TINET for authentication!             =")
        logger.warning("⚠️ = People won't need to provide valid credentials to use     =")
        logger.warning("⚠️ = any username they want, this might cause issues, please   =")
        logger.warning("⚠️ = put your online-mode field back to true in the [server]   =")
        logger.warning("⚠️ = section in server.properties to ensure max. security!     =")
        logger.warning("⚠️ = It is recommended to run the server in online mode for    =")
        logger.warning("⚠️ = improved security and authentication.                     =")
        logger.warning("⚠️ " + "=" * 53)

    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(
        (
            config.get('server', 'host', fallback="127.0.0.1"),
            config.getint('server', 'port', fallback=2052)
        )
    )
    server_socket.settimeout(1)
    server_socket.listen(5)
    logger.info(
        f"Server listening on "
        f"{config.get('server', 'host', fallback="127.0.0.1")}"
        f":"
        f"{config.getint('server', 'port', fallback=2052)}"
    )

    clients = []

    SERVER_ONLINE = True

    try:
        while SERVER_ONLINE:
            try:
                client_socket, client_address = server_socket.accept()
            except TimeoutError:
                continue
            clients.append(client_socket)
            client_thread = threading.Thread(target=handle_client, args=(client_socket, client_address, clients))
            client_thread.start()
    except KeyboardInterrupt:
        logger.info("Shutting down the server.")
        logger.info(f"This might take some time since we are announcing {len(clients)} clients.")
        client_index = 0
        for client_socket in clients:
            logger.debug(f"Closing client {client_index}/{len(clients)}.")
            client_socket.sendall(b"SERVER_SHUTDOWN")
            time.sleep(100)
            client_socket.close()
        server_socket.close()

        SERVER_ONLINE = False

        for thread in threading.enumerate():
            if thread != threading.current_thread():
                thread.join()


if __name__ == "__main__":
    main()
