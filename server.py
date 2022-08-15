import argparse
from socket import AF_INET, socket, SOCK_STREAM
from threading import Thread
from threading import Event as ThreadEvent
import time
import pickle
import sys, os
import json
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto.PublicKey import RSA
import random, string
from base64 import b64encode
from base64 import b64decode
msg_log = []
msg_show = 25

class CryptoCipher:
    def __init__(self,client):
        self.key = None
        self.private_key = None
        self.public_key = None
        self.client_public_key = None
        self.session_key = None
        self.client = client
        self.bytes = 32
        self.rsa_bits = 2048
        self.tcpbyte = 4096
        self.successful = "Neutral" #Neutral, positive, negative, ERROR

    def protocol_deserialize(self,bytes_r=4096):
        msg = self.client.recv(bytes_r)
        loaded = json.loads(msg.decode("utf-8"))
        return loaded

    def protocol_serialize(self,message):
        msg = json.dumps(message).encode("utf-8")
        self.client.send(msg)
       
    def AES_Send(self,message,bytes=1024): # Send message via AES
        cipher = AES.new(self.session_key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(message)
        json_v = [ b64encode(x).decode('utf-8') for x in (nonce, ciphertext, tag)]
        json_k = ['nonce', 'ciphertext', 'tag']
        result = json.dumps(dict(zip(json_k, json_v))).encode("utf-8")
        self.client.send(result)

    def AES_recv(self,bytes=1024) -> bytes: # Receive message via AES
        json_k = ['nonce', 'ciphertext', 'tag']
        bytesr = self.client.recv(bytes)
        b64 = json.loads(bytesr.decode("utf-8"))
        datar = {k:b64decode(b64[k]) for k in json_k}
        nonce = datar["nonce"]
        tag = datar["tag"]
        ciphertext = datar["ciphertext"]
        cipher = AES.new(self.session_key, AES.MODE_EAX, nonce=nonce)
        plaintext = cipher.decrypt(ciphertext)
        try:
            cipher.verify(tag)
            return plaintext
        except ValueError:
            print("Message is not authentic rejected")
            return ""

    def hello_handshake(self):
        print("performing handshake")
        self.client.settimeout(30)
        try:
            c_hello = self.protocol_deserialize()
        except socket.timeout as e:
            print("Client failure handshake Timeout")
            return False
        except json.JSONDecodeError as e:
            print("Client invalid message")
            return False
        finally:
            self.client.settimeout(None)
        if c_hello != "":
            if "client" in c_hello:
                c_message = c_hello["client"]
                if c_message == "ReadyProtocolV25":
                    server_hello = {"server": "HolaProtocolaV25","bytes": self.bytes}
                    server_hello["rsa-bits"] = self.rsa_bits
                    self.protocol_serialize(server_hello)
                    self.client.settimeout(None)
                    return True
                else:
                    server_hello = {"error": "incorrect protocol"}
                    self.protocol_serialize(server_hello)          
        else:
            print("Client disconnect")
        #Clear client timeout
        self.client.settimeout(None)
        return False

    def Client_Server_Keyswap(self):
        print("performing pkey swap")
        self.successful = "Neutral"
        self.client.settimeout(30)
        try:
            client_resp = self.protocol_deserialize()
        except socket.timeout as e:
            print("Client failure handshake Timeout")
            return False
        except json.JSONDecodeError as e:
            print("Client invalid message")
            return False
        finally:
            self.client.settimeout(None)
        if client_resp != "":
            if "client" in client_resp:
                c_message = client_resp["client"]
                if "key_public_client" in c_message:
                    server_pub = {"server": {"key_public_server":self.public_key}}
                    self.protocol_serialize(server_pub)
                    self.client_public_key = RSA.import_key(c_message["key_public_client"])
                    #Now we receive the client key we send server public key
                    self.client.settimeout(None)
                    self.successful = "positive"
                    return True
                else:
                    server_hello = {"error": "key not found"}
                    self.protocol_serialize(server_hello)
                    self.successful = "ERROR"       
        else:
            print("Client disconnect")
        #Clear client timeout
        self.successful = "negative"
        self.client.settimeout(None)
        return False

    #Generate session keys
    def generate_private(self):
        key = RSA.generate(self.rsa_bits)
        self.private_key = key

    def generate_public(self):
        pk = self.private_key.public_key()
        self.public_key = pk.export_key(format='PEM').decode()

    def generate_session(self):
        key = ''.join(random.SystemRandom().choice(string.ascii_uppercase + string.digits) for _ in range(self.bytes))
        return key.encode("utf-8")
            
    def S_Pencrypt(self,json_message):
        msg = json.dumps(json_message).encode("utf-8")
        cipher = PKCS1_OAEP.new(self.client_public_key)
        c = cipher.encrypt(msg)
        self.client.send(c)

    def S_Pdecrypt(self):
        msg = self.client.recv(2048)
        cipher = PKCS1_OAEP.new(self.private_key)
        message = cipher.decrypt(msg)
        loaded = json.loads(message.decode("utf-8"))
        return loaded

    def Send_aeskey(self):
        self.session_key = self.generate_session()
        client_pub = {"server": {"secret":self.session_key.decode("utf-8")}}
        self.S_Pencrypt(client_pub)
        return True
    


def message_log_handler():
    if len(msg_log) >= msg_show:
        msg_top = msg_log[-msg_show:]
    elif len(msg_log) < msg_show and not len(msg_log) == 0:
        msg_top = msg_log[0:len(msg_log)]
    else:
        msg_top = []
    modified_msg_log = msg_top
    return modified_msg_log 

def auto_save_logmessage(event):
    while event.is_set():
        save_log_message()
        time.sleep(60)

def save_log_message():
    with open("msg_log.pkl","wb") as f:
        pickle.dump(msg_log, f)
    
def init_msg_log():
    global msg_log
    try:
        with open("msg_log.pkl","rb") as f:
            msg_log = pickle.load(f)
    except FileNotFoundError:
        print("Could not find msg_log no message history will be loaded")
    except EOFError:
        print("EOF error could not load messages")


def accept_incoming_connections():
    """Sets up handling for incoming clients."""
    while True:
        client, client_address = SERVER.accept()
        print("%s:%s has connected." % client_address)
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,client_address,)).start()


def handle_client(client,client_address):  # Takes client socket as argument.
    """Handles a single client connection."""
    Enc_obj = CryptoCipher(client)
    if Enc_obj.hello_handshake():
        Enc_obj.generate_private()
        Enc_obj.generate_public()
        if Enc_obj.Client_Server_Keyswap():
            print("Handshake Successful")
            Enc_obj.Send_aeskey()
            client_obj = Client(client,Enc_obj,client_address)
            client_obj.Communication_Loop() #Thread will block here indefinetly till the communication stops
        else:
            print("Handshake unsuccesful")
    else:
        print("Incorrect Hello")
    


class Client:
    def __init__(self,socket,crypto_ident,address) -> None:
        self.client = socket #Sock Object
        self.crypto = crypto_ident #Has to be a CryptoCipher object
        self.client_Address = address

    def Communication_Loop(self):
        name = ""
        prefix = ""
        while True:
            msg = receive_decoded_message(self.client,encryption=self.crypto)

            if not msg is None:
                msg = msg

            if msg == "":
                msg = "{QUIT}"

            # Avoid messages before registering
            if "ALL" in msg and name:
                recv_msg = msg["ALL"]
                new_msg = format_message("MSG",f"{prefix} {recv_msg}",encryption=self.crypto)
                msg_log.append(format_message("MSG",f"{prefix} {recv_msg}",raw=True))
                send_message(new_msg, broadcast=True)
                continue

            if "REGISTER" in msg:
                name = msg["REGISTER"]
                if duplicate_name(name): # kicks client if the name is duplicate
                    print("%s:%s has been forcefully disconnected." % self.client_Address)
                    reject = format_message("KICK", "Connection Denied from the server; Duplicate name, please change it")
                    send_message(reject, destination=self)
                    time.sleep(2)
                    sys.exit()
                clients[self] = name
                prefix = name + ": "
                send_clients()
                time.sleep(0.5)
                msg_history = format_message("LOGS", {"type": "msg_logs","content": message_log_handler()})
                send_message(msg_history,destination=self)
                time.sleep(0.5)
                welcome = format_message("MSG", f"Welcome {name}!")
                send_message(welcome, destination=self)
                msg = format_message("MSG", f"{name} has joined the chat!")
                send_message(msg, broadcast=True)
                continue

            if "QUIT" in msg:
                print("%s:%s has promptly disconnected." % self.client_Address)
                self.client.close()
                try:
                    del clients[self.client]
                except KeyError:
                    pass
                if name:
                    send_message(format_message("MSG", f"{name} has left the chat."), broadcast=True)
                    send_clients()
                break

            # Avoid messages before registering
            if not name:
                continue
            # We got until this point, it is either an unknown message or for an
            # specific client...
            try:
                if "PRIV" in msg:
                    sendto_name = msg["PRIV"]["name"]
                    priv_message = msg["PRIV"]["message"]
                    origin_name = msg["PRIV"]["origin"]
                    destination_name = msg["PRIV"]["destination"]
                    priv_whole = f"{origin_name}->{destination_name}: {priv_message}"

                    dest_sock = find_client_socket(sendto_name)
                    msg_params = format_message("PRIV",{"origin":origin_name,"message":priv_whole})
                if dest_sock:
                    send_message(msg_params, prefix=prefix, destination=dest_sock)
                else:
                    print("Invalid Destination. %s" % sendto_name)
            except Exception as e:
                exc_type, exc_obj, exc_tb = sys.exc_info()
                fname = os.path.split(exc_tb.tb_frame.f_code.co_filename)[1]
                reject = format_message("KICK", "Connection Denied from the server; Invalid client reponse")
                print(exc_type, fname, exc_tb.tb_lineno,"client kicked")
                send_message(reject, destination=self)
                clients.pop(self.client)
                sys.exit()

    def send(self,msg):
        self.crypto.AES_Send(msg.encode("utf-8"))

    def close(self):
        try:
            reject = format_message("KICK", "Disconnected from the server; server closed")
            send_message(reject, destination=self)
        except Exception as e:
            print(f"Cannot establish close request: {e}")
        self.client.close()

    def __del__(self):
        print("Client deleted")
        clients.pop(self)
    



def send_clients():
    client_list = format_message("CLIENTS",get_clients_names())
    send_message(client_list, broadcast=True)


def get_clients_names(separator="|", default=True):
    names = []
    for _, name in clients.items():
        names.append(name)
    if default:
        return separator.join(names)
    else:
        return names

def duplicate_name(selected_name):
    names = get_clients_names(default=False)
    for name in names:
        if selected_name == name:
            return True
        else:
            return False


def find_client_socket(name):
    for cli_sock, cli_name in clients.items():
        if cli_name == name:
            return cli_sock
    return None

def close_clients():
    for cli in clients:
        try:
            cli.close()
            clients.pop(cli)
        except OSError as e:
            print("Cannot close: ",e)


def send_message(msg, prefix="", destination=None, broadcast=False): #Binary should be expected into msg argument
    # send_msg = bytes(prefix + msg, "utf-8")
    send_msg = msg
    if broadcast:
        """Broadcasts a message to all the clients."""
        for cli in list(clients):
            try:
                cli.send(send_msg)
            except OSError:
                print("disconnected inactive clients")
                clients.pop(cli)
    else:
        if destination is not None:
            destination.send(send_msg)

def format_message(key, data,encryption=False,raw=False) -> dict:
    """Set dict message and convert it into a sendable binary"""
    msg = {}
    msg[key] = data
    if not raw:
        binmsg = json.dumps(msg)
    else:
        binmsg = msg
    return binmsg

def receive_decoded_message(client,encryption: CryptoCipher = None) -> dict:
        """Receive and decode pickled binary"""
        try:
            data = encryption.AES_recv(BUFSIZ)
        except ConnectionResetError as e:
            return ""
        if data != "":
            binmsg = json.loads(data.decode("utf-8"))
            return binmsg
        return ""







clients = {}
addresses = {}

parser = argparse.ArgumentParser(description="Chat Server")
parser.add_argument(
    '--host',
    help='Host IP',
    default="127.0.0.1"
)
parser.add_argument(
    '--port',
    help='Port Number',
    default=33002
)

server_args = parser.parse_args()

init_msg_log()

HOST = server_args.host
PORT = int(server_args.port)
BUFSIZ = 4096
ADDR = (HOST, PORT)

stop_server = False

SERVER = socket(AF_INET, SOCK_STREAM)
SERVER.bind(ADDR)

if __name__ == "__main__":
    try:
        SERVER.listen(5)
        print("Server Started at {}:{}".format(HOST, PORT))
        print("Waiting for connection...")
        EVENT = ThreadEvent()
        EVENT.set()
        ACCEPT_THREAD = Thread(target=accept_incoming_connections)
        HISTORY_SAVE = Thread(target=auto_save_logmessage, args=(EVENT,))
        ACCEPT_THREAD.start()
        HISTORY_SAVE.start()
        ACCEPT_THREAD.join()
        EVENT.clear()
        SERVER.close()
        save_log_message()
    except KeyboardInterrupt:
        print("Closing...")
        save_log_message()
        close_clients()
        HISTORY_SAVE.interrupt()
        ACCEPT_THREAD.interrupt()
