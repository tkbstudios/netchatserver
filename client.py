import os
import sys
import socket
import logging
from colorlog import ColoredFormatter
import dotenv

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


dotenv_loaded = dotenv.load_dotenv('.env')
if not dotenv_loaded:
    logger.error("No `.env` found!")
    sys.exit(1)

NETCHAT_SERVER_HOST = os.environ.get("NETCHAT_SERVER_HOST", default="netchat.tkbstudios.com")
NETCHAT_SERVER_PORT = int(os.environ.get("NETCHAT_SERVER_PORT", default=2052))
TINET_USERNAME = os.environ.get("TINET_USERNAME")
TINET_CALC_KEY = os.environ.get("TINET_CALC_KEY")

if __name__ == "__main__":
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    logger.info(f"Connecting to the NETCHAT server at {NETCHAT_SERVER_HOST}:{NETCHAT_SERVER_PORT} ...")
    client_socket.connect((NETCHAT_SERVER_HOST, NETCHAT_SERVER_PORT))
    logger.info(f"Connected to the NETCHAT server at {NETCHAT_SERVER_HOST}:{NETCHAT_SERVER_PORT} !")
    logger.info(f"Logging in... (username: {TINET_USERNAME})")
    authenticated = False
    client_socket.send(f"AUTH:{TINET_USERNAME}:{TINET_CALC_KEY}".encode())
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
    while True:
        recipient = input("Recipient: ")
        message_to_send = input("Message to send: ")
        client_socket.send(f"{recipient}:{message_to_send}".encode())
        logger.info("Sent!")