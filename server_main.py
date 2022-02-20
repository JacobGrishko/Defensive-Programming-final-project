import socket
import threading
import struct
import UMassageDB


VERSION = 2
REQ_1000 = 1000
REQ_1001 = 1001
REQ_1002 = 1002
REQ_1003 = 1003
REQ_1004 = 1004

ANS_2000 = 2000
ANS_2001 = 2001
ANS_2002 = 2002
ANS_2003 = 2003
ANS_2004 = 2004
ANS_9000 = 9000

ID_LEN = 16
MAX_PACKAGE_LEN = 1024

REQ_HEADER_LEN = 23
REQ_1003_HDR_LEN = 21
REQ_1000_HDR_LEN = 415

ANS_HEADER_LEN = 7
ANS_2001_HDR_LEN = 271
ANS_2004_HDR_LEN = 25
SYMM_KEY_CIPHER_LEN = 128

class Server:
    def __init__(self, host, port):
        self.HOST = host
        self.PORT = port
        self.s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.s.bind((HOST, PORT))
        self.db = UMassageDB.database()

    '''*****************************************************************************'''
    '''
    revc_all function recives all the data in a loop and returns the whole msg
    '''
    def recv_all(self, s):
        print("got conn")
        full_msg = ""
        while True:
            chunk = s.recv(32)
            if "\0" in chunk.decode() or len(chunk) == 0:
                full_msg += chunk.decode()
                break
            full_msg += chunk.decode()
        return full_msg

    '''*****************************************************************************'''
    '''
    send_err function returns an error header
    '''
    def send_err(self,conn):
        version = VERSION
        code = ANS_9000
        payload_size = 0
        replydata = struct.pack('<BHI', version, code, payload_size)
        newdata = bytearray(ANS_HEADER_LEN)
        for i in range(min(len(replydata), len(newdata))):
            newdata[i] = replydata[i]
        conn.sendall(newdata)

    '''*****************************************************************************'''
    '''
    send_msg function sends an answer header
    '''
    def send_msg(self, conn, msg_code, pl_size):
        print("try to send back answer")
        version = VERSION
        code = msg_code
        payload_size = pl_size
        replydata = struct.pack('<BHI', version, code, payload_size)

        newdata = bytearray(ANS_HEADER_LEN)
        print("new bytearray")
        for i in range(min(len(replydata), len(newdata))):
            newdata[i] = replydata[i]

        conn.sendall(newdata)
        print("Header was sent.")
        pass

    '''*****************************************************************************'''
    '''
    send_pl function sends a payload
    '''
    def send_pl(self, conn, payload):
        pl = payload
        conn.sendall(pl)
        print("payload was sent.")
        pass

    '''*****************************************************************************'''
    '''
    get_msg function receives a request
    1.get the header of the request
    2.check if user exists, if not, send back an error header 
    3.if
    '''
    def get_msg(self, conn, addr):
        print("waiting for a message from {0}".format(addr))
        data = conn.recv(REQ_HEADER_LEN)
        print(data)
        unpacked = struct.unpack('<16sBHI', data)
        clientID = unpacked[0]
        ver = unpacked[1]
        req_code = unpacked[2]
        plSize = unpacked[3]
        print("{0}:id: {1}. ver: {2}, code is: {3}, pl size: {4}".format(addr, clientID, ver, req_code, plSize))

        # check that the client exists
        cl_exist = self.db.client_exist(clientID)

        if cl_exist == -1 and req_code != REQ_1000:
            self.send_err(conn)
            return

        if req_code == REQ_1000:
            print("registering a client...")
            pl = conn.recv(REQ_1000_HDR_LEN)
            up_pl = struct.unpack('<255s160s', pl)

            # add name and uuid to users list
            new_id = self.db.add_client(up_pl[0], up_pl[1])

            # if success, return new uuid
            if new_id != -1:
                payload = new_id
                self.send_msg(conn, ANS_2000, ID_LEN)
                self.send_pl(conn, payload)
                print("New client {0} was registered.".format(up_pl[0]))
            else:
                self.send_err(conn)

        elif req_code == REQ_1001 and cl_exist:
            print("returning list of clients...")
            clients = self.db.ret_clients(clientID)
            print("got clients")
            self.send_msg(conn, ANS_2001, len(clients) * ANS_2001_HDR_LEN)
            for client in clients:
                client_id = client[0]
                name = client[1]
                pl = client_id + struct.pack('<255s', name)
                self.send_pl(conn, pl)
            print("Clients were sent to {0}".format(addr))

        elif req_code == REQ_1002 and cl_exist:
            print("Returning public key of a client...")
            # extract users key
            pl = conn.recv(ID_LEN)
            print("looking for id...")
            res = self.db.ret_cl_pubKey(pl)
            if res != -1:
                client_id = res[0]
                pub_key = res[1]
                pl = client_id + struct.pack('<160s', pub_key)
                payload = pl

                self.send_msg(conn, ANS_2002, ID_LEN)
                self.send_pl(conn, payload)
                print("Public key was sent back to {0}".format(addr))
            else:
                self.send_err(conn)

        elif req_code == REQ_1003 and cl_exist:
            print("Receiving a message")
            pl = conn.recv(REQ_1003_HDR_LEN)
            up_pl = struct.unpack('<16s B I', pl)
            dest_client = up_pl[0]
            msg_type = up_pl[1]
            content_size = up_pl[2]
            content = ""

            if msg_type == 2:
                content = conn.recv(SYMM_KEY_CIPHER_LEN)

            if msg_type == 3 or msg_type == 4:
                total = content_size
                content = bytearray()
                while total > 0:
                    bytes_to_recv = min(content_size, MAX_PACKAGE_LEN)
                    new_content = conn.recv(bytes_to_recv)
                    total = total - len(new_content)
                    content = b''.join([content, new_content])

            db_ret = self.db.save_message(clientID, dest_client, msg_type, content)

            if db_ret != -1:
                self.send_msg(conn, ANS_2003, ID_LEN)
                clid = db_ret[0]
                msg_id = db_ret[1]
                packed_id = struct.pack('<I', msg_id)
                payload = clid + packed_id

                self.send_pl(conn, payload)
                print("Message was received and an answer was send back to {0}".format(addr))
            else:
                self.send_err(conn)

        elif req_code == REQ_1004 and cl_exist:
            print("returning messages...")
            messages = self.db.ret_messages(clientID)
            content_size = 0
            for msg in messages:
                content_size = content_size + msg[3]
            print("total {0} bytes of content.".format(content_size))
            self.send_msg(conn, ANS_2004, ANS_2004_HDR_LEN * len(messages) + content_size)
            for msg in messages:
                client_id = msg[0]
                msg_id = msg[1]
                msg_type = msg[2]
                msg_size = msg[3]
                content = msg[4]

                if msg_type == '1':
                    payload = client_id + struct.pack('<IcI', msg_id, msg_type.encode('ascii'), msg_size)
                else:
                    payload = client_id + struct.pack('<IcI', msg_id, msg_type.encode('ascii'), msg_size) + content

                self.send_pl(conn, payload)
        else:
            self.send_err(conn)

        conn.close()
        print("end of request")

    '''*****************************************************************************'''
    '''
    listen function accepts new connections and opens a thread to take care of the request
    '''
    def listen(self):
        while True:
            try:
                print("listening...")
                self.s.listen()
                conn, addr = self.s.accept()
                print('Connected by', addr)
                clientHandler = threading.Thread(target=self.get_msg, args=(conn, addr)).start()
            except:
                print("could not open socket")


'''*****************************************************************************'''
'''
get_port function reads the port for the server
'''
def get_port(filename):
    with open(filename, "r") as file:
        return int(file.readline())


# host and port init
HOST = ''
PORT = get_port("port.info")

print("opening server")
my_server = Server(HOST, PORT)
print("starting a listener")
my_server.listen()
clientHandler = threading.Thread(target=my_server.listen())
