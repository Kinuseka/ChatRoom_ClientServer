#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import platform
from pydoc import plain
Client_Version_Header = 0.25 #Current client version
#Client version - must be a float 
#Client machine - OS the client is on {p_os: platformOS, p_rl: platformSystem, p_ver: platformVersion}
client_details_header = [
    Client_Version_Header,
    {"p_os": platform.system(),"p_rl": platform.system(),"p_ver":platform.version()}
]
"""
Created on Tue Jul 24 13:05:46 2018

@forked by: Kinuseka
v25
Added RSA and AES message encryption
v24
Disconnect to server when server sends kick request and message history fetch.
v23 
Use dictionaries instead of strings when sending messages (easier data handling and more precise packet handling, it prevents formatting errors when messages are sent too fast)

@author: JC
v22
invalid port, just set back to default and display message
v21
Close event, a prompt to assure
v20
first github push
v19
Emoji!!!!
v18
Verify IP input
v17
Fix scroll to the second last line
v16
Refacotring
v15
grid layout for home tab, adding IP, port entering, exception handling when connection refused
v14
If the receiver leave before message sent, display the "Not Delivered"
v13
html format display
v12
Fix name entering line lock bug
v11
Improve UI, scroll area keep bottom view
v10
Improve UI, layout
v9
Working on friend's list
v8
Working on "send to"
v7
Working on connection re-making
v6
Working on thread improvement for receiving socket

REFERENCE

Grid Layout
http://zetcode.com/gui/pyqt5/layout/

Scrollable
https://stackoverflow.com/questions/47930677/pythonpyqt5-how-to-use-qscrollarea-for-one-or-many-qgroupbox

QListView
https://www.pythoncentral.io/pyside-pyqt-tutorial-qlistview-and-qstandarditemmodel/

HTML color picker
https://www.w3schools.com/colors/colors_picker.asp

Window close event
https://stackoverflow.com/questions/40622095/pyqt5-closeevent-method
"""
import socket
import sys
import threading
import time
import functools
from PyQt5 import QtCore, QtGui
from PyQt5 import QtWidgets
from PyQt5.QtWidgets import QMainWindow, QApplication, QWidget, QPushButton
from PyQt5.QtWidgets import QVBoxLayout, QHBoxLayout, QMessageBox, QTabWidget
from PyQt5.QtWidgets import QGridLayout, QScrollArea, QLabel, QListView
from PyQt5.QtWidgets import QLineEdit, QComboBox, QGroupBox, QAction
from PyQt5.QtGui import QStandardItemModel, QStandardItem, QFont
import pickle
import json

class MyTableWidget(QWidget):
    def __init__(self, parent):
        super(QWidget, self).__init__(parent)
        #connecion
        self.conn = socket.socket()
        self.connected = False
        #tab UI
        self.layout = QVBoxLayout(self)
        self.tabs = QTabWidget()
        self.tabs.resize(300,200)        
        self.tab1 = QWidget()
        self.tab2 = QWidget()
        self.tabs.addTab(self.tab1, "Home")
        self.tabs.addTab(self.tab2, "Chat Room")
        self.tabs.setTabEnabled(1,False)
        self.tabs.currentChanged.connect(self.tabSelected) #Track tab changes
        self.tabrefreshed = False
        #<Home>
        gridHome = QGridLayout()
        self.tab1.setLayout(gridHome)
        self.IPBox = QGroupBox("IP")
        self.IPLineEdit = QLineEdit()
        self.IPLineEdit.setText("127.0.0.1")
        IPBoxLayout = QVBoxLayout()
        IPBoxLayout.addWidget(self.IPLineEdit)
        self.IPBox.setLayout(IPBoxLayout)
        self.portBox = QGroupBox("port")
        self.portLineEdit = QLineEdit()
        self.portLineEdit.setText("33002")
        portBoxLayout = QVBoxLayout()
        portBoxLayout.addWidget(self.portLineEdit)
        self.portBox.setLayout(portBoxLayout)
        self.nameBox = QGroupBox("Name")
        self.nameLineEdit = QtWidgets.QLineEdit()
        nameBoxLayout = QVBoxLayout()
        nameBoxLayout.addWidget(self.nameLineEdit)
        self.nameBox.setLayout(nameBoxLayout)
        self.connStatus = QLabel("Status", self)
        font = QFont()
        font.setPointSize(16)
        self.connStatus.setFont(font)
        self.connBtn = QPushButton("Connect")
        self.connBtn.clicked.connect(self.__connect_thread_handler)
        self.disconnBtn = QPushButton("Disconnect")
        self.disconnBtn.clicked.connect(self.disconnect_server)
        gridHome.addWidget(self.IPBox,0,0,1,1)
        gridHome.addWidget(self.portBox,0,1,1,1)
        gridHome.addWidget(self.nameBox,1,0,1,1)
        gridHome.addWidget(self.connStatus,1,1,1,1)
        gridHome.addWidget(self.connBtn,2,0,1,1)
        gridHome.addWidget(self.disconnBtn,2,1,1,1)
        gridHome.setColumnStretch(0, 1)
        gridHome.setColumnStretch(1, 1)
        gridHome.setRowStretch(0, 0)
        gridHome.setRowStretch(1, 0)
        gridHome.setRowStretch(2, 9)
        #</Home>
        #<Chat Room>
        gridChatRoom = QGridLayout()
        self.tab2.setLayout(gridChatRoom)
        self.messageRecords = QLabel("<font color=\"#000000\">Welcome to chat room</font>", self)
        self.messageRecords.setStyleSheet("background-color: white;")
        self.messageRecords.setAlignment(QtCore.Qt.AlignTop)
        self.messageRecords.setAutoFillBackground(True)
        self.scrollRecords = QScrollArea()
        self.scrollRecords.verticalScrollBar().rangeChanged.connect(
        self.scrollToBottom,
        )
        self.scrollRecords.setWidget(self.messageRecords)
        self.scrollRecords.setWidgetResizable(True)
        self.sendTo = "ALL"
        self.sendChoice = QLabel("Send to :ALL", self)
        self.displayUsername = QLabel("Name:", self)
        self.sendComboBox = QComboBox(self)
        self.sendComboBox.addItem("ALL")
        self.sendComboBox.activated[str].connect(self.send_choice)
        self.lineEdit = QLineEdit()
        self.lineEnterBtn = QPushButton("Enter")
        self.lineEnterBtn.clicked.connect(self.enter_line)
        self.lineEdit.returnPressed.connect(self.enter_line)
        self.friendList = QListView()
        self.friendList.setWindowTitle('Room List')
        self.model = QStandardItemModel(self.friendList)
        self.friendList.setModel(self.model)
        self.emojiBox = QGroupBox("Emoji")
        self.emojiBtn1 = QPushButton("ก็ʕ•͡ᴥ•ʔ ก้")
        self.emojiBtn1.clicked.connect(functools.partial(self.send_emoji, "ก็ʕ•͡ᴥ•ʔ ก้"))
        self.emojiBtn2 = QPushButton("(｡◕∀◕｡)")
        self.emojiBtn2.clicked.connect(functools.partial(self.send_emoji, "(｡◕∀◕｡)"))
        self.emojiBtn3 = QPushButton("( ˘･з･)")
        self.emojiBtn3.clicked.connect(functools.partial(self.send_emoji, "( ˘･з･)"))
        self.emojiBtn4 = QPushButton("ᕦ(ò_óˇ)ᕤ")
        self.emojiBtn4.clicked.connect(functools.partial(self.send_emoji, "ᕦ(ò_óˇ)ᕤ"))
        emojiLayout = QHBoxLayout()
        emojiLayout.addWidget(self.emojiBtn1)
        emojiLayout.addWidget(self.emojiBtn2)
        emojiLayout.addWidget(self.emojiBtn3)
        emojiLayout.addWidget(self.emojiBtn4)
        self.emojiBox.setLayout(emojiLayout)
        gridChatRoom.addWidget(self.scrollRecords,0,0,1,3)
        gridChatRoom.addWidget(self.friendList,0,3,1,1)
        gridChatRoom.addWidget(self.sendComboBox,1,0,1,1)
        gridChatRoom.addWidget(self.sendChoice,1,2,1,1)
        gridChatRoom.addWidget(self.displayUsername,1,1,1,1)
        gridChatRoom.addWidget(self.lineEdit,2,0,1,3)
        gridChatRoom.addWidget(self.lineEnterBtn,2,3,1,1)
        gridChatRoom.addWidget(self.emojiBox,3,0,1,4)
        gridChatRoom.setColumnStretch(0, 9)
        gridChatRoom.setColumnStretch(1, 9)
        gridChatRoom.setColumnStretch(2, 9)
        gridChatRoom.setColumnStretch(3, 1)
        gridChatRoom.setRowStretch(0, 9)
        #</Chat Room>
        #Initialization
        self.layout.addWidget(self.tabs)
        self.setLayout(self.layout) 
        self.msg_logs = []       
        self.connBtn.setEnabled(True)
        self.disconnBtn.setEnabled(False)

    def scrollToBottom (self, minVal=None, maxVal=None):
        # Additional params 'minVal' and 'maxVal' are declared because
        # rangeChanged signal sends them, but we set it to optional
        # because we may need to call it separately (if you need).
    
        self.scrollRecords.verticalScrollBar().setValue(
        self.scrollRecords.verticalScrollBar().maximum()
        )
    def tabSelected(self, arg=None):
        """Refreshes when user has been out in the tabs"""
        if arg == 1 and not self.tabrefreshed: #Run function on Thread to prevent clogging up the main thread
            self.tabrefreshed = True
            thread = threading.Thread(target=self.__tab_update)
            thread.start()
            
    def __tab_update(self):
        oldText = self.messageRecords.text()
        appendText = "<font color=\"#000000\">Refreshing...</font>"
        self.messageRecords.setText(appendText)
        self.scrollRecords.verticalScrollBar().setValue(self.scrollRecords.verticalScrollBar().maximum())
        time.sleep(0.02)
        self.messageRecords.setText(oldText)
        self.scrollRecords.verticalScrollBar().setValue(self.scrollRecords.verticalScrollBar().maximum())
        self.tabrefreshed = False

    def __connect_thread_handler(self):
        def _button_connect_server(connectservfunc):
            if not connectservfunc():
                self.connBtn.setEnabled(True)
        thread = threading.Thread(target=_button_connect_server, args=(self.connect_server,))
        thread.start()



    def enter_line(self):
        #assure the person still in rooom before send out
        if self.sendTo != self.sendComboBox.currentText():
            self.message_display_append("The person left. Private message not delivered")
            self.lineEdit.clear()
            return
        line = self.lineEdit.text()
        if line == "":#prevent empty message
            return
        if self.sendTo != "ALL":#private message, send to myself first
            #this is a trick leverage the server sending back a copy to myself
            send_msg = self.format_message(f"PRIV", {"name": self.userName, "origin": self.userName,"destination": self.sendTo, "message": line})
            self.send_encrypt(send_msg)
            time.sleep(0.1) #this is important for not overlapping two sending
            send_msg = self.format_message(f"PRIV", {"name": self.sendTo, "origin": self.userName, "destination": self.sendTo , "message": line})
            self.send_encrypt(send_msg)
        elif self.sendTo == "ALL":
            send_msg = self.format_message("ALL",line)
            self.send_encrypt(send_msg)

        self.lineEdit.clear()
        self.scrollRecords.verticalScrollBar().setValue(self.scrollRecords.verticalScrollBar().maximum())
        
    def send_emoji(self, emoji):
        #assure the person still in rooom before send out
        if not self.emoji_buttons:
            return
        if self.sendTo != self.sendComboBox.currentText():
            self.message_display_append("The person left. Private message not delivered")
            return
        if self.sendTo != "ALL":#private message, send to myself first
            #this is a trick leverage the server sending back a copy to myself
            send_msg = self.format_message(f"PRIV", {"name": self.userName, "origin": self.userName,"destination": self.sendTo, "message": emoji})
            self.send_encrypt(send_msg)
            time.sleep(0.1) #this is important for not overlapping two sending
            send_msg = self.format_message(f"PRIV", {"name": self.sendTo, "origin": self.userName, "destination": self.sendTo , "message": emoji})
            self.send_encrypt(send_msg)
        elif self.sendTo == "ALL":
            send_msg = self.format_message("ALL",emoji)
            self.send_encrypt(send_msg)
        #emoji list:
        #(ﾉ◕ヮ◕)ﾉ*:･ﾟ#(｡◕∀◕｡)#ก็ʕ•͡ᴥ•ʔ ก้#(´･_･`)#ᕦ(ò_óˇ)ᕤ#(•ө•)#( ˘･з･)
        #(〒︿〒)#(╥﹏╥)#(灬ºωº灬)#（つ> _◕）つ︻╦̵̵͇̿̿̿̿╤───#(╬▼дﾟ)▄︻┻┳═一
    
    def message_display_append(self, newMessage, textColor = "#000000",update=True):
        oldText = self.messageRecords.text()
        appendText = oldText+"<br /><font color=\""+textColor+"\">"+newMessage+"</font><font color=\"#000000\"></font>"
        self.messageRecords.setText(appendText)
        time.sleep(0.02)
        if update: #this helps the bar set to bottom, after all message already appended
            self.scrollRecords.verticalScrollBar().setValue(self.scrollRecords.verticalScrollBar().maximum())
            self.scrollRecords.verticalScrollBar().setValue(self.scrollRecords.verticalScrollBar().maximum())
        
    def receive_encrypt(self):
        try:
            data = self.encoder.AES_recv(BUFSIZ)
        except Exception as e:
            
            data = ""
        return data

    def send_encrypt(self,msg):
        try:
            self.encoder.AES_Send(msg)
        except Exception as e:
            import logging
            print(logging.exception("error"))
            self.message_display_append(f"[Client] Error sending message: {e}")

    def receive_decoded_message(self):
        """Receive and decode a serialized dict"""
        try:
            data = self.receive_encrypt()
            if data != "":
                try:
                    binmsg = json.loads(data.decode("utf-8"))
                    return binmsg
                except EOFError:
                    return ""
                except ConnectionResetError as e:
                    return {"KICK","Client connection error; Disconnected from the server"}
                except UnicodeDecodeError as e:
                    self.message_display_append(f"[Client] Could not decode message: {e}")
                    return ""
        except Exception as e:
            self.message_display_append(f"[Client] Received invalid message: {e}")
                
        return ""
    
    def format_message(self,key,data):
        """Set dict message and convert it into a sendable binary"""
        msg = {}
        msg[key] = data
        binmsg = json.dumps(msg).encode("utf-8")
        return binmsg
        
    def message_log(self, data):
        self.msg_logs.append(data)


    def updateRoom(self):
        while self.connected:
            data = self.receive_decoded_message()
            print(data)
            if data != "":
                if "CLIENTS" in data:
                    welcome = data["CLIENTS"]
                    self.update_send_to_list(welcome)
                    self.update_room_list(welcome)
                    if not welcome[0][5:] == "":
                        self.message_display_append(welcome[0][5:])
                elif "LOGS" in data:
                    logs_data = data["LOGS"]
                    if logs_data["type"] == "msg_logs":
                        print('it goes here')
                        self.show_history(logs_data["content"])
                    elif logs_data["type"] == "up_notice" :
                        self.message_display_append(logs_data["content"], "#3AFF37")
                    elif logs_data["type"] == "depr_notice":
                        self.message_display_append(logs_data["content"], "#FF4747")
                    elif logs_data["type"] == "info_notice":
                        self.message_display_append(logs_data["content"], "#00FFFF")

                elif "MSG" in data: #{MSG} includes broadcast and server msg
                    self.message_display_append(data["MSG"], "#006600")
                    self.message_log(data)
                elif "KICK" in data: #{CLI} handles when server kicks a client
                    self.message_display_append(data["KICK"], "#FF5959")
                    self.message_log(data)
                    self.unload_server(reason_text="Server Denied")
                elif "PRIV" in data: #private messgage is NONE format
                    priv_message = data["PRIV"]["message"]
                    priv_complete = f"{priv_message}"
                    self.message_display_append(priv_complete, "#cc33cc")
                    self.message_log(data)
                else:
                    print("Received unknown message protocol")
            time.sleep(0.1) #this is for saving thread cycle time
            
    def connect_server(self):
        if self.connected == True:
            return
        self.connBtn.setEnabled(False)
        name = self.nameLineEdit.text()
        if name == "":
            self.connStatus.setText("Status :"+"Please enter your name")
            return False
        self.userName = name
        IP = self.IPLineEdit.text()
        if IP == "":
            IP = "127.0.0.1"
        port = self.portLineEdit.text()
        if port == "" or not port.isnumeric():
            self.portLineEdit.setText("33002")
            self.connStatus.setText("Status :"+"Port format invalid")
            return False
        else:
            port = int(port)
        try:
            self.conn.connect((IP, port))
        except Exception as e:
            print(e)
            self.connStatus.setText("Status :"+" Refused")
            self.conn = socket.socket()
            return False
        self.connStatus.setText("Status :"+" Performing handshake")
        time.sleep(0.2)
        self.encoder = CryptoCipher(self.conn)
        try:
            if self.encoder.hello_handshake():
                self.connStatus.setText("Status :"+" Generating session keys(1/2)")
                self.encoder.generate_private()
                self.connStatus.setText("Status :"+" Generating session keys(2/2)")
                self.encoder.generate_public()
                self.connStatus.setText("Status :"+" Acquiring server keys")
                if self.encoder.Client_Server_Keyswap():
                    print("Handshake Successful")
                    self.encoder.fetch_aeskey()
                else:
                    print("Handshake unsuccesful")
                    self.connStatus.setText("Status :"+" Handshake unsuccessful")
                    return False
            else:
                print("Incorrect Hello")
                return False
        except Exception as e:
            import logging
            print(logging.exception("error"))
            self.connStatus.setText("Status :"+" error occured while initiating secure connection")
            self.conn = socket.socket()
            return False

        client_creds = {"userName": name, "clientID": hash(name),"token": None,"clientDetails": client_details_header}
        send_msg = self.format_message("REGISTER",name)
        self.send_encrypt(send_msg)
        self.connected = True 
        self.connStatus.setText("Status :"+" Connected")
        self.nameLineEdit.setReadOnly(True) #This setting is not functional well
        #Enable buttons and emojis if disabled
        self.lineEdit.setReadOnly(False) #Enable chat line
        self.emoji_buttons = True #Enable Emojis 
        self.lineEnterBtn.setEnabled(True) #Enable enter button
        self.disconnBtn.setEnabled(True)
        #--
        if not self.tabs.isTabEnabled(1):
            self.tabs.setTabEnabled(1,True)
        self.rT = threading.Thread(target= self.updateRoom)
        self.rT.start()
        return True

    def unload_server(self,reason_text=False): #When a forceful disconnect happens such as a KICK response
        if self.connected == False:
            return
        if not reason_text:
            self.connStatus.setText("Status :"+" Disconnected")
        elif isinstance(reason_text,str):
            self.connStatus.setText("Status :"+" "+reason_text)
        else:
            self.connStatus.setText("Status :"+" Unknown")
        self.nameLineEdit.setReadOnly(False)
        #Disable buttons and emojis but keep chatbox open
        self.lineEdit.setReadOnly(True) #Disable chat line
        self.emoji_buttons = False #Disable Emojis 
        self.lineEnterBtn.setEnabled(False) #Disable enter button
        self.connBtn.setEnabled(True)
        # self.tabs.setTabEnabled(1,False)
        #--
        self.connected = False
        self.rT.join()
        self.conn.close()
        self.conn = socket.socket()
        

    def disconnect_server(self,reason_text=False): #Normal deattachment to the server
        if self.connected == False:
            return
        # Declare a QUIT response to the server for a graceful quit
        send_msg = self.format_message("QUIT","")
        self.send_encrypt(send_msg)
        if not reason_text:
            self.connStatus.setText("Status :"+" Disconnected")
        elif isinstance(reason_text,str):
            self.connStatus.setText("Status :"+" "+reason_text)
        else:
            self.connStatus.setText("Status :"+" Unknown")
        self.nameLineEdit.setReadOnly(False)
        #Disable buttons and emojis but keep chatbox open
        self.lineEdit.setReadOnly(True) #Disable chat line
        self.emoji_buttons = False #Disable Emojis 
        self.lineEnterBtn.setEnabled(False) #Disable enter button
        self.connBtn.setEnabled(True)
        # self.tabs.setTabEnabled(1,False)
        #--
        self.connected = False
        self.rT.join()
        self.conn.close()
        self.conn = socket.socket()

    def show_history(self, logs):
        """LOAD SERVER HISTORY CHAT LOGS DO NOT OUTPUT IF THE MESSAGE ALREADY EXISTS"""
        # t = threading.Thread(target=self.__proc_show_history, args=(logs,))
        # t.daemon = True
        # t.start()
        self.__proc_show_history(logs)
        self.scrollRecords.verticalScrollBar().setValue(self.scrollRecords.verticalScrollBar().maximum())
        
    def __proc_show_history(self,logs):
        for line in logs:
            ready = True
            if "MSG" in line: #{MSG} includes broadcast and server msg
                for local_line in self.msg_logs:
                    if "MSG" in local_line: #{MSG} includes broadcast and server msg
                        if line == local_line:
                            ready = False
                else:
                    if ready:
                        self.message_display_append(line["MSG"], "#006600",update=False)
                        self.message_log(line)
                       
                        

                    

        
    def update_room_list(self, strList):
        L = strList.split("|")
        self.model.clear()
        for person in L:
            item = QStandardItem(person)
            item.setCheckable(False)
            self.model.appendRow(item)
        
    def update_send_to_list(self, strList):
        L = strList.split("|")
        self.sendComboBox.clear()
        self.sendComboBox.addItem("ALL")
        for person in L:
            if person != self.userName:
                self.sendComboBox.addItem(person)
        previous = self.sendTo
        index = self.sendComboBox.findText(previous)
        print("previous choice:",index)
        if index != -1:
            self.sendComboBox.setCurrentIndex(index) #updating, maintain receiver
        else:
            self.sendComboBox.setCurrentIndex(0) #updating, the receiver left, deafault to "ALL"
        
    def send_choice(self,text):
        self.sendTo = text
        print(self.sendTo)
        self.sendChoice.setText("Send to: "+text)




class Window(QMainWindow):
    def __init__(self):
        super(Window, self).__init__()
        self.setGeometry(50, 50, 500, 300)
        self.setWindowTitle("Chat-Client")        
        self.table_widget = MyTableWidget(self)
        self.setCentralWidget(self.table_widget)
        self.show()
        
    def closeEvent(self, event):
        close = QMessageBox()
        close.setText("You sure?")
        close.setStandardButtons(QMessageBox.Yes | QMessageBox.Cancel)
        close = close.exec()
        if close == QMessageBox.Yes:
            self.table_widget.disconnect_server() #disconnect to server before exit
            event.accept()
        else:
            event.ignore()

from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP, AES
from Crypto import Random
from Crypto.Util.Padding import pad, unpad
from hashlib import md5
from base64 import b64encode
from base64 import b64decode

class CryptoCipher:
    def __init__(self,client):
        self.key = None
        self.private_key = None
        self.public_key = None
        self.client_public_key = None
        self.session_key = None
        self.client = client
        self.bytes = 16
        self.rsa_bits = None
        self.successful = "Neutral" #Neutral, positive, negative, ERROR

    def protocol_deserialize(self,bytes_r=4096):
        msg = self.client.recv(bytes_r)
        loaded = json.loads(msg.decode("utf-8"))
        return loaded

    def protocol_serialize(self,message):
        msg = json.dumps(message).encode("utf-8")
        self.client.send(msg)

    def AES_Send(self,message,bytes=1024): # Send message via AES encryption
        json_k = ['nonce', 'ciphertext', 'tag']
        cipher = AES.new(self.session_key, AES.MODE_EAX)
        nonce = cipher.nonce
        ciphertext, tag = cipher.encrypt_and_digest(message)
        json_v = [ b64encode(x).decode('utf-8') for x in (nonce, ciphertext, tag)]
        result = json.dumps(dict(zip(json_k, json_v))).encode("utf-8")
        self.client.send(result)


    def AES_recv(self,bytes=1024) -> bytes: # Receive message via AES encryption
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

    def hello_handshake(self): #initiate and synchronize handshake with protocol versions
        print("performing handshake")
        self.client.settimeout(30)
        client_hello = {"client": "ReadyProtocolV25"}
        self.protocol_serialize(client_hello)
        try:
            s_hello = self.protocol_deserialize()
        except socket.timeout as e:
            print("Se failure handshake Timeout")
            return False
        except json.JSONDecodeError as e:
            print("Client invalid message")
            return False
        finally:
            self.client.settimeout(None)
        if s_hello != "":
            if "server" in s_hello:
                c_message = s_hello["server"]
                if c_message == "HolaProtocolaV25": 
                    self.bytes = s_hello["bytes"]
                    self.rsa_bits = s_hello["rsa-bits"]
                    self.client.settimeout(None)
                    return True
                else:
                    print("Client unsupported protocol")
                    return False  
            elif "error" in s_hello:
                print("server: "+s_hello["error"])   
        else:
            print("Client disconnect")
        #Clear client timeout
        self.client.settimeout(None)
        return False

    def Client_Server_Keyswap(self): #Swap Public key initiate
        print("performing pkey swap")
        self.successful = "Neutral"
        self.client.settimeout(30)
        client_pub = {"client": {"key_public_client":self.public_key}}
        self.protocol_serialize(client_pub)
        try:
            server_resp = self.protocol_deserialize()
        except socket.timeout as e:
            print("Client failure handshake Timeout")
            return False
        except json.JSONDecodeError as e:
            print("Client invalid message")
            return False
        finally:
            self.client.settimeout(None)
        if server_resp != "":
            if "server" in server_resp:
                c_message = server_resp["server"]
                if "key_public_server" in c_message:
                    self.client_public_key = RSA.import_key(c_message["key_public_server"])
                    #Now we receive the client key we send server public key
                    self.client.settimeout(None)
                    self.successful = "positive"
                    return True
                else:
                    print("key not found")
                    self.successful = "ERROR"     
            elif "error" in server_resp:
                print("server: "+ server_resp["error"])  
        else:
            print("Client disconnect")
        #Clear client timeout
        self.successful = "negative"
        self.client.settimeout(None)
        return False

    #Generate session keys
    def generate_private(self): #Generate unique private key 
        key = RSA.generate(self.rsa_bits)
        self.private_key = key

    def generate_public(self): #Generate unique public key
        pk = self.private_key.public_key()
        self.public_key = pk.export_key(format="PEM").decode()
            
    def S_Pencrypt(self,json_message): #Send VIA RSA encryption
        msg = json.dumps(json_message).encode("utf-8")
        cipher = PKCS1_OAEP.new(self.client_public_key)
        c = cipher.encrypt(msg)
        self.client.send(c)

    def S_Pdecrypt(self): #Receive VIA RSA encryption
        # sk = open("secret_key.pem").read()
        # key = RSA.import_key(sk)
        # cipher = PKCS1_OAEP.new(key)
        # m = cipher.decrypt(crypted_m)
        # del sk
        # del key
        # del cipher
        # return m
        msg = self.client.recv(2048)
        cipher = PKCS1_OAEP.new(self.private_key)
        message = cipher.decrypt(msg)
        loaded = json.loads(message.decode("utf-8"))
        return loaded

    def fetch_aeskey(self):
        key = self.S_Pdecrypt()
        strkey = str(key["server"]["secret"])
        self.session_key = strkey.encode("utf-8") 
        return True


    def encrypt(self,message):
        msg = json.dumps(message).encode("utf-8")
        cipher = PKCS1_OAEP.new(self.client_public_key)
        c = cipher.encrypt(msg)
        self.client.send(c)

    def decrypt(self,message):
        msg = self.client.recv(2048)
        cipher = PKCS1_OAEP.new(self.private_key)
        message = cipher.decrypt(loaded)
        loaded = json.loads(message.decode("utf-8"))
        return message


BUFSIZ = 4096
def run():
    app = QApplication(sys.argv)
    GUI = Window()
    sys.exit(app.exec_())

if __name__ == "__main__":
    run()    
