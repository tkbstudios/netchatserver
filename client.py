import os
import sys
import socket
import logging
import threading
from datetime import datetime, timedelta

import requests
from colorlog import ColoredFormatter
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

dotenv_loaded = dotenv.load_dotenv('.env')
if not dotenv_loaded:
    logger.error("No `.env` found!")
    sys.exit(1)

TINET_BASE_API_URL = "https://tinet.tkbstudios.com/api"

NETCHAT_SERVER_HOST = os.environ.get("NETCHAT_SERVER_HOST", default="netchat.tkbstudios.com")
NETCHAT_SERVER_PORT = int(os.environ.get("NETCHAT_SERVER_PORT", default=2052))
TINET_USERNAME = os.environ.get("TINET_USERNAME")
TINET_CALC_KEY = os.environ.get("TINET_CALC_KEY")


def get_session_token(username, calc_key):
    session_token_file = 'session.txt'
    if os.path.exists(session_token_file):
        with open(session_token_file, 'r') as file:
            token = file.read()
            if len(token) == 1:
                logger.info("Using the token from session.txt, checking token...")
                auth_with_session_token_url = f"{TINET_BASE_API_URL}/v1/user/sessions/auth"
                headers = {
                    "Content-Type": 'application/json',
                    "Accept": 'application/json'
                }
                body = {
                    "username": username,
                    "session_token": token
                }
                logger.debug("send POST request to API to check token")
                session_token_request = requests.post(auth_with_session_token_url, headers=headers, json=body)
                logger.debug(f"request status code: {session_token_request.status_code}")
                if session_token_request.status_code == 200:
                    user_data = session_token_request.json()
                    print(user_data)
                    if user_data['username'] == username:
                        logger.info("Token is valid")
                        return token
                    else:
                        logger.info("Token invalid, requesting a new one.")

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
            expiration_time = datetime.now() + timedelta(hours=10)
            with open(session_token_file, 'w') as file:
                file.write(f"{session_token}\n{expiration_time.isoformat()}")
            return session_token
        else:
            return False
    return None


def receive_messages(socket_conn):
    while True:
        try:
            recv_msg_bytes = socket_conn.recv(1024)
            if recv_msg_bytes:
                recv_bytes_decoded = recv_msg_bytes.decode().strip()
                recv_msg_data = recv_bytes_decoded.split(":", 2)
                if len(recv_msg_data) == 3:
                    recv_recipient, recv_username, recv_msg = recv_msg_data
                    logger.info(f"{recv_username}: {recv_msg}")
                else:
                    logger.error(f"Could not send message! Response from server: {recv_bytes_decoded}")
            else:
                logger.error("Disconnected from server.")
                break
        except Exception as e:
            logger.error(f"Error receiving message: {e}")
            break


if __name__ == "__main__":
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.info(f"Connecting to the NETCHAT server at {NETCHAT_SERVER_HOST}:{NETCHAT_SERVER_PORT} ...")
    client_socket.connect((NETCHAT_SERVER_HOST, NETCHAT_SERVER_PORT))
    logger.info(f"Connected to the NETCHAT server at {NETCHAT_SERVER_HOST}:{NETCHAT_SERVER_PORT} !")
    logger.info(f"Logging in... (username: {TINET_USERNAME})")
    logger.info("Requesting a session token for service...")
    service_session_token = get_session_token(TINET_USERNAME, TINET_CALC_KEY)
    authenticated = False
    client_socket.send(f"AUTH:{TINET_USERNAME}:{service_session_token}".encode())
    while True:
        recv_bytes = client_socket.recv(128)
        if not authenticated:
            if len(recv_bytes) > 0:
                if recv_bytes.decode() == "AUTH_SUCCESS":
                    authenticated = True
                    logger.info("Logged in successfully!")
                    break
                else:
                    logger.error(f"Couldn't log in! {recv_bytes.decode()}")
                    sys.exit(1)

    logger.info("You can now chat with other people!")

    receive_thread = threading.Thread(target=receive_messages, args=(client_socket,))
    receive_thread.daemon = True
    receive_thread.start()

    while True:
        recipient = input("Recipient: ")
        message_to_send = input("Message to send: ")
        client_socket.send(f"{recipient}:{message_to_send}".encode())
        logger.info("Sent!")
