import sqlite3
from datetime import datetime
import uuid


class database():

    '''
    init function creates a db and two tables
    '''
    def __init__(self):
        try:
            self.db_name = 'server.db'
            self.conn = sqlite3.connect(self.db_name)
            self.c = self.conn.cursor()
            table1 = "CREATE TABLE clients(" \
                     "ID varchar(16)," \
                     " Name varchar(255)," \
                     " PublicKey VarChar(160)," \
                     "LastSeen TIMESTAMP)"
            table2 = "CREATE TABLE messages(" \
                     "ID integer NOT NULL PRIMARY KEY AUTOINCREMENT," \
                     " ToClient varchar(16)," \
                     " FromClient varchar(16)," \
                     "Type varchar(1)," \
                     " Content Blob)"
            self.c.execute(table1)
            self.c.execute(table2)
            self.conn.commit()
            self.conn.close()

        except sqlite3.Error as err:
            print("got error: {0}".format(err))

    '''*****************************************************************************'''
    '''connect_database function connects to the database'''
    def connect_database(self):
        try:
            self.conn = sqlite3.connect(self.db_name)
            self.c = self.conn.cursor()
        except sqlite3.OperationalError as err:
            print(err)

    '''*****************************************************************************'''
    '''add_client function saves a client and return his new UUID'''
    def add_client(self,new_name,new_pubkey):
        try:
            self.connect_database()
        except sqlite3.Error as err:
            print("connecting problem {0}".format(err))
            return -1
        with self.conn:
            try:
                #check if name exists in the table
                query = "SELECT * FROM clients WHERE Name=:name"
                self.c.execute(query, {'name':new_name})
                exist = self.c.fetchone()
                if(exist):
                    return -1
                #add new client to table
                print("adding public key: {0}".format(new_pubkey))
                query = "INSERT INTO clients VALUES (:id,:name,:pubkey,:time)"
                id = uuid.uuid4().bytes_le
                # id = uuid.uuid4().hex
                now = datetime.now()
                self.c.execute(query, {'id':id, 'name': new_name, 'pubkey':new_pubkey, 'time':now})
                print("added {0}".format(id))
                return id
            except sqlite3.Error as err:
                print("add client: {0}".format(err))
                return -1

    '''*****************************************************************************'''
    '''client_exist function checks if a client exists, and updates the time of last request'''
    def client_exist(self, clID):
        try:
            self.connect_database()
        except sqlite3.Error as err:
            print("connecting problem {0}".format(err))
            return -1
        with self.conn:
            try:
                #check if name exists in the table
                query = "SELECT * FROM clients WHERE ID=:clID"
                self.c.execute(query, {'clID':clID})
                exist = self.c.fetchone()
                if(exist):
                    #UPDATE REQUEST TIME OF THE CLIENT
                    now = datetime.now()
                    query = "UPDATE clients SET LastSeen=:new_time WHERE ID=:clID"
                    self.c.execute(query, {'clID': clID,'new_time':now})
                    print("last seen time updated to {0}".format(now))
                    return 1
                return -1
            except sqlite3.Error as err:
                print("add client: {0}".format(err))
                return -1

    '''*****************************************************************************'''
    '''ret_clients function returns all the clients except the client who sent the request'''
    def ret_clients(self, clID):
        try:
            self.connect_database()
        except sqlite3.Error as err:
            print("connecting problem {0}".format(err))
            return -1
        with self.conn:
            try:
                query = "SELECT ID,Name FROM clients WHERE NOT (ID=:client)"
                self.c.execute(query,{'client':clID})
                return self.c.fetchall()
            except sqlite3.Error as err:
                print("ret clients: {0}".format(err))
                return -1

    '''*****************************************************************************'''
    '''ret_cl_pubKey function returns a public key of a requested client'''
    def ret_cl_pubKey(self,clID):
        try:
            self.connect_database()
        except sqlite3.Error as err:
            print("connecting problem {0}".format(err))
            return -1
        with self.conn:
            try:
                print("checking in database for {0}".format(clID))
                query = "SELECT ID,PublicKey FROM clients WHERE ID=:clID"
                self.c.execute(query,{'clID':clID})
                return self.c.fetchone()
            except sqlite3.Error as err:
                print("ret pub key: {0}".format(err))
                return -1

    '''*****************************************************************************'''
    '''save_message function saves a message and returns the ID of the new message'''
    def save_message(self,fromClient, toClient, type, content):
        try:
            self.connect_database()
            print("db connected...")
        except sqlite3.Error as err:
            print("connecting problem {0}".format(err))
            return -1
        with self.conn:
            try:
                query = "INSERT INTO messages (FromClient,ToClient,Type,Content) VALUES (:from,:to,:type,:content)"
                self.c.execute(query, {'from': fromClient, 'to': toClient, 'type': type, 'content': content})
                clID = toClient
                return clID,self.c.lastrowid
            except sqlite3.Error as err:
                print("save message: {0}".format(err))
                return -1

    '''*****************************************************************************'''
    '''ret_messages function returns all messages of a client, and the deletes them'''
    def ret_messages(self, clID):
        try:
            self.connect_database()
        except sqlite3.Error as err:
            print("connecting problem {0}".format(err))
            return -1
        with self.conn:
            try:
                query = "SELECT fromClient,ID,Type,length(Content),Content FROM messages WHERE ToClient=:to"
                self.c.execute(query, {'to': clID})
                answer = self.c.fetchall()
                query = "DELETE FROM messages WHERE ToClient=:to"
                self.c.execute(query, {'to': clID})
                return answer
            except sqlite3.Error as err:
                print("ret messages: {0}".format(err))
                return -1

    '''*****************************************************************************'''
    '''close_connection function closes the connection to the database'''
    def close_connection(self):
        print("closing connection")
        if self.conn is not None:
            self.conn.close()
            print("closed.")
