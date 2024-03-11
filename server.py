import os
import random
import socket
import string
import sys
import threading
import requests
import logging
from colorlog import ColoredFormatter
import time
import configparser
import dotenv
import shutil

logger = logging.getLogger(__name__)
logger.setLevel(logging.INFO)

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

dotenv.load_dotenv('.env')


class Server:
    def __init__(self):
        self.setup_files_and_directories()
        self.update_server_properties()
        self.sessions = {}
        self.client_sockets = {}
        self.user_last_message_time = {}
        self.config = configparser.ConfigParser()
        self.config.read('server.properties')
        self.PUBLIC_ACCESS_HOST = self.config.get('server', 'public-access-host', fallback="no address set")
        self.WELCOME_MESSAGE_ENABLED = self.config.getboolean('server', 'enable-welcome-message', fallback=False)
        self.WELCOME_MESSAGE = self.config.get('server', 'welcome-message', fallback="There's no welcome message set!")
        self.MAX_MESSAGE_LENGTH = self.config.getint('server', 'max-message-length', fallback=256)
        self.ANNOUNCE_NEW_USERS = self.config.getboolean('server', 'announce-new-clients', fallback=True)
        self.APP_API_KEY = os.environ.get("APP_API_KEY").strip()
        self.SERVER_ONLINE = False
        self.clients = []
        self.server_socket = None
        self.shutdown_requested = False

    @staticmethod
    def setup_files_and_directories():
        changed_anything = False

        if not os.path.exists("server.properties"):
            logger.error("`server.properties` NOT found! Copying the example over.")
            if os.path.exists("server.properties.example"):
                shutil.copyfile("server.properties.example", "server.properties")
                logger.info("Copied `server.properties.example` over to `server.properties`.")
                logger.info("Please edit the `server.properties`.")
                changed_anything = True

        if not os.path.exists(".env"):
            logger.error("`.env` NOT found! Copying the example over.")
            if os.path.exists(".env.example"):
                shutil.copyfile(".env.example", ".env")
                logger.info("Copied `.env.example` over to `.env`.")
                logger.info("Please edit the `.env`.")
                changed_anything = True

        if changed_anything:
            sys.exit(0)

    @staticmethod
    def update_server_properties():
        # Makes sure server.properties keeps being updated with new values.
        changed_anything = False
        if os.path.exists("server.properties.example") and os.path.exists("server.properties"):
            example_config = configparser.ConfigParser()
            example_config.read("server.properties.example")

            server_config = configparser.ConfigParser()
            server_config.read("server.properties")

            for section in example_config.sections():
                if section not in server_config:
                    server_config[section] = {}
                    changed_anything = True
                for key, value in example_config[section].items():
                    if key not in server_config[section]:
                        server_config[section][key] = value
                        changed_anything = True
            if changed_anything:
                with open("server.properties", "w") as server_properties_file:
                    server_config.write(server_properties_file)
                logger.info("Updated `server.properties` with new keys from `server.properties.example`.")

    def get_user_data_from_api(self, username):
        session_token = self.sessions.get(username)
        if session_token:
            auth_with_session_token_url = f"https://tinet.tkbstudios.com/api/v1/user/sessions/auth"
            headers = {
                "Content-Type": 'application/json',
                "Accept": 'application/json',
                "Api-Key": self.APP_API_KEY
            }
            body = {
                "username": username,
                "session_token": session_token
            }
            session_token_request = requests.post(auth_with_session_token_url, headers=headers, json=body)
            if session_token_request.status_code == 200:
                user_data = session_token_request.json()
                return True, user_data
            else:
                if 'error' in session_token_request.json():
                    if session_token_request.json()['error'] == "User has not granted access to the app":
                        return None, session_token_request.json()['grant_url']
        return None, None

    def check_rate_limit(self, username):
        last_message_time = self.user_last_message_time.get(username)
        if last_message_time is not None:
            elapsed_time = time.time() - last_message_time
            if elapsed_time < 1:
                time.sleep(1 - elapsed_time)

    def send_to_webhook(self, username, message):
        if self.config.getboolean('discord', 'hook-enabled', fallback=False):
            hook_url = self.config.get('discord', 'hook-url', fallback=None)
            if hook_url:
                body = {
                    "username": f"[NETCHAT] {username} "
                                f"({self.PUBLIC_ACCESS_HOST})",
                    "content": message
                }
                hook_post_request = requests.post(hook_url, json=body)
                if hook_post_request.status_code == 200:
                    logger.debug(f"Sent `{message}` to Discord hook.")

    def send_to_recipient(self, recipient, sender_username, message):
        clean_msg = self.clean_message(message)
        bytes_to_send = f"{recipient}:{sender_username}:{clean_msg}\n".encode()

        if recipient == "global":
            self.send_to_webhook(sender_username, clean_msg)
            for client in self.clients:
                client.sendall(bytes_to_send)
        else:
            recipient_socket = self.get_socket_from_username(recipient)
            if recipient_socket:
                logger.debug(f"Sending to recipient socket! {recipient_socket}")
                recipient_socket.sendall(bytes_to_send)

            else:
                logger.info(f"Recipient '{recipient}' not found or offline.")

        logger.debug(f"{sender_username} sent `{clean_msg}` to {recipient}.")

    def get_socket_from_username(self, username):
        if username in self.client_sockets:
            return self.client_sockets[username]
        return None

    @staticmethod
    def clean_message(message_to_clean):
        cleaned_message = message_to_clean.replace("@everyone", "[everyone mention tried]")
        cleaned_message = cleaned_message.replace("@here", "[here mention tried]")
        return cleaned_message

    def handle_client(self, client_socket, client_address):
        logger.debug(f"Accepted connection from {client_address}")

        authenticated = False
        username = None

        while self.SERVER_ONLINE:
            try:
                data = client_socket.recv(2048)
                if not data:
                    break

                received_message = data.decode().strip()

                if not authenticated:
                    if received_message.startswith("AUTH:"):
                        parts = received_message.split(":")
                        if len(parts) == 3:
                            _, received_username, received_session_token = parts
                            session_token = received_session_token
                            if not self.config.getboolean('server', 'online-mode', fallback=True):
                                authenticated = True
                                session_token = ''.join(
                                    random.choice(string.ascii_letters + string.digits) for _ in range(256)
                                )
                                username = received_username
                                self.sessions[username] = session_token
                                self.client_sockets[username] = client_socket
                                logger.info(f"{username} has logged in! OFFLINE MODE")
                                if self.ANNOUNCE_NEW_USERS:
                                    self.send_to_recipient(
                                        "global",
                                        "[server]",
                                        f"{username} has joined (OFFLINE MODE)!"
                                    )
                                client_socket.sendall(b"AUTH_SUCCESS\n")
                            else:
                                if session_token:
                                    username = received_username
                                    self.sessions[received_username] = session_token
                                    self.client_sockets[username] = client_socket
                                    success, response = self.get_user_data_from_api(received_username)
                                    if success and response:
                                        authenticated = True
                                        client_socket.sendall(b"AUTH_SUCCESS\n")
                                        logger.debug(
                                            f"User {username} authenticated successfully. User data: {response}")
                                        if self.WELCOME_MESSAGE_ENABLED:
                                            welcome_message_to_send = f"WELCOME_MESSAGE:{self.WELCOME_MESSAGE}"
                                            client_socket.sendall(welcome_message_to_send.encode())
                                        if self.ANNOUNCE_NEW_USERS:
                                            self.send_to_recipient("global", "[server]", f"{username} has joined!")
                                    else:
                                        if response:
                                            client_socket.sendall(
                                                f"AUTH_FAILED:"
                                                f"Please grant this app access to your account here: "
                                                f"{response}"
                                                .encode())
                                        client_socket.sendall(b"AUTH_FAILED:Could not get user data from TINET\n")
                                else:
                                    if received_username in self.sessions:
                                        self.sessions.pop(received_username)
                                    if received_username in self.client_sockets:
                                        self.client_sockets.pop(received_username)
                                    client_socket.sendall(b"AUTH_FAILED:No valid session token\n")
                                    logger.warning(f"Authentication failed for user {received_username}.")
                        else:
                            client_socket.sendall(b"ERROR:Invalid message format\n")
                    else:
                        client_socket.sendall(b"AUTH_REQUIRED\n")
                else:
                    if ":" in received_message:
                        recipient, message = received_message.split(":", 1)
                        recipient = recipient.strip()
                        message = message.strip()
                        message = message[:self.MAX_MESSAGE_LENGTH]
                        if len(recipient) < 3:
                            client_socket.sendall(
                                b"ERROR:Invalid message format (recipient must be at least 3 characters)\n"
                            )
                            continue

                        if len(message) == 0:
                            client_socket.sendall(
                                b"ERROR:You can't send an empty message...\n"
                            )
                            continue

                        self.check_rate_limit(username)
                        self.user_last_message_time[username] = time.time()
                        self.send_to_recipient(recipient, username, message)
                    else:
                        client_socket.sendall(b"ERROR:Invalid message format\n")
            except Exception as e:
                logger.error(f"Error: {e}")
                break

        self.clients.remove(client_socket)
        client_socket.close()
        if username in self.sessions:
            self.sessions.pop(username)
        if username in self.client_sockets:
            self.client_sockets.pop(username)
        logger.debug(f"Connection from {client_address} closed")

    def start(self):
        # load and check settings
        if not self.config.getboolean('server', 'online-mode', fallback=True):
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

        self.server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_socket.bind(
            (
                self.config.get('server', 'host', fallback="127.0.0.1"),
                self.config.getint('server', 'port', fallback=2052)
            )
        )
        self.server_socket.settimeout(1)
        self.server_socket.listen(5)
        logger.info(
            f"Server listening on "
            f"{self.config.get('server', 'host', fallback='127.0.0.1')}"
            f":"
            f"{self.config.getint('server', 'port', fallback=2052)}"
        )

        self.SERVER_ONLINE = True

        try:
            while self.SERVER_ONLINE:
                try:
                    client_socket, client_address = self.server_socket.accept()
                except TimeoutError:
                    continue
                self.clients.append(client_socket)
                client_thread = threading.Thread(target=self.handle_client, args=(client_socket, client_address))
                client_thread.start()
        except KeyboardInterrupt:
            self.shutdown_requested = True
            logger.info("Shutting down the server.")
            logger.info(f"This might take some time since we are announcing {len(self.clients)} clients.")
            client_index = 0
            for client_socket in self.clients:
                logger.debug(f"Closing client {client_index}/{len(self.clients)}.")
                client_socket.sendall(b"SERVER_SHUTDOWN")
                time.sleep(100)
                client_socket.close()
            self.server_socket.close()

            self.SERVER_ONLINE = False

            for thread in threading.enumerate():
                if thread != threading.current_thread():
                    thread.join()


if __name__ == "__main__":
    server = Server()
    server.start()
