import cherrypy
import urllib.request
import json
import base64

import nacl.secret
import nacl.utils
import nacl.pwhash
import nacl.encoding
import nacl.signing
from nacl.public import PrivateKey, SealedBox
import time
from time import strftime
import sqlite3
import socket
import threading
import queue

import os
from jinja2 import Environment, select_autoescape, FileSystemLoader


#Grab the current working directory.
CUR_DIR = os.getcwd()

#Create an environment object, used to load templates.
env = Environment(loader=FileSystemLoader(CUR_DIR), autoescape=select_autoescape(['html', 'xml']))

clientAddress = socket.gethostbyname(socket.gethostname())+':10050'

#global address list, updated periodically by javascript call to /update endpoint.
activeAddresses = []


class MainApp(object):

    #CherryPy Configuration
    _cp_config = {'tools.encode.on': True, 
                  'tools.encode.encoding': 'utf-8',
                  'tools.sessions.on' : 'True',
                 }       

    #404 page to catch unknown endpoints.
    @cherrypy.expose
    def default(self, *args, **kwargs):
        """The default page, given when we don't recognise where the request is for."""
        
        template = env.get_template('templates/index.html')
        cherrypy.response.status = 404
        return template.render()


    @cherrypy.expose
    def update(self):
        """discovers new users, updates existing user statuses, pings all addresses, assigns active addresses to global list reports any active users as 'online'"""

        if not (cherrypy.session.get('username') == None):

            #report the user as online
            global clientAddress
            login = reportUser(publicKey=cherrypy.session.get('pubKey'), username=cherrypy.session.get('username'), password=cherrypy.session.get('password'), status='online', connectionAddress=clientAddress)
            if (login['response'] == 'ok'):
                print("SUCCESSFULLY REPORTED "+cherrypy.session.get('username'))

            try:
                #grab a list of online users.
                userData = listUsers(cherrypy.session.get('username'), cherrypy.session.get('password'))
                users = userData['users']

                #discover new users, update existing users pubkeys/statuses and update active address list.
                global activeAddresses
                activeAddresses = getConnectedWebapps(users, cherrypy.session.get('username'), cherrypy.session.get('password'), clientAddress)
                discoverUsers(users)
            except (KeyError, TypeError, urllib.error.URLError, TimeoutError, ConnectionResetError):
                print("FAILED TO UPDATE DATA") 


    @cherrypy.expose
    def index(self):
        """home page, most functions redirect here; displays public messages and online users"""

        try:  
            
            if not (cherrypy.session.get('username') == None):
                
                userData = listUsers(cherrypy.session.get('username'), cherrypy.session.get('password'))
                users = userData['users']

                usernames = []
                for user in users:
                    usernames.append(user['username'])
					

                #Grab public broadcasts from the database.
                connect = sqlite3.connect("broadcasts.db")
                cursor = connect.cursor()

                cursor.execute("select record, message, sendTime, signature  from publicMessages ORDER by sendTime DESC")
                rows = cursor.fetchall()

                connect.commit()
                connect.close()

                messageUserList = []
                messages = []
                messageDateList = []

                #add each broadcast to a list and send it to the jinja2 template to be printed on the page.
                for row in rows:

                    senderLoginData = row[0]
                    senderDataList = senderLoginData.split(',')
                    senderUsername = senderDataList[0]

                    message = row[1]
                    timestamp = row[2]

                    time_Date = time.localtime(timestamp)
                    time_Str = strftime("%a, %d %b %Y at %H:%M:%S", time_Date)

                    messageUserList.append(senderUsername)
                    messages.append(message)
                    messageDateList.append(time_Str)


                template = env.get_template('/templates/home.html')
                return template.render(username=cherrypy.session.get('username'), users=usernames, loggedIn=True, messages=messages, messageuserlist=messageUserList, messagedatelist=messageDateList, reloadpage=True)

            else:
                raise KeyError

        #raised session has expired/there is active user.
        except (KeyError, TypeError):
            
            template = env.get_template('/templates/index.html')
            return template.render(loggedIn=False, reloadpage=False)
        

    @cherrypy.expose
    def login(self, bad_attempt=0):
        """login page, if bad_attempt!=0 then invalid credentials message is displayed to the user"""
        if bad_attempt != 0:
            badAttempt = True
        else:
            badAttempt = False

        template = env.get_template('/templates/login.html')
        return template.render(badAttempt=badAttempt, loggedIn=False)


    @cherrypy.expose
    def broadcast(self):
        """page for sending public/private messages"""

        template = env.get_template('/templates/broadcast.html')
        return template.render(loggedIn=True, reloadpage=False)


    @cherrypy.expose
    def private_messages(self):
        """Page that displays all private messages in the database for the logged in user"""

        #Grab private messages from the database.
        connect = sqlite3.connect("broadcasts.db")
        cursor = connect.cursor()

        cursor.execute("select record, targetPubkey, targetUsername, encryptedMessage, receivedTime from privateMessages ORDER by receivedTime DESC")
        rows = cursor.fetchall()

        connect.commit()
        connect.close()

        messageUserList = []
        messages = []
        messageDateList = []

        #for each entry in the database attempt to decrypt and display the message, if the user is not the correct user the decryption will fail
        #and the message wont be displayed.
        for row in rows:

            senderLoginData = row[0]
            senderDataList = senderLoginData.split(',')
            senderUsername = senderDataList[0]
            
            targetPubkey = row[1]
            targetUsername = row[2]
            encryptedMessage = bytes(row[3], 'utf-8')
            timestamp = row[4]

            time_Date = time.localtime(timestamp)
            time_Str = strftime("%a, %d %b %Y at %H:%M:%S", time_Date)

            if (cherrypy.session.get('username') == targetUsername):
                try:
                    targetPrivateKeyCurve = cherrypy.session.get('privKey').to_curve25519_private_key()
                    unseal_box = nacl.public.SealedBox(targetPrivateKeyCurve)

                    message_bytes = unseal_box.decrypt(encryptedMessage, encoder=nacl.encoding.HexEncoder)
                    message = message_bytes.decode('utf-8')

                    messageUserList.append(senderUsername)
                    messages.append(message)
                    messageDateList.append(time_Str)

                #exception will be raised if the decryption fails (current user is not the target user of the message: their private key cant decrypt the message)
                except nacl.exceptions.CryptoError as error:
                    pass

        template = env.get_template('/templates/privateMessages.html')
        return template.render(username=cherrypy.session.get('username'), messages=messages, messageuserlist=messageUserList, messagedatelist=messageDateList, loggedIn=True, reloadpage=True)
        

    @cherrypy.expose
    def sendPublicbroadcast(self, pubmessage=None):
        """Send a public Broadcast to all connected users"""

        userData = listUsers(cherrypy.session.get('username'), cherrypy.session.get('password'))
        users = userData['users']

        #global list of active addresses that have recently responded to /ping_check, loop through and send the public message to each.
        global activeAddresses

        for address in activeAddresses:
            print("SENDING TO: "+address)
            url = url = "http://"+address+"/api/rx_broadcast"

            try:
                broadcast = pubBroadcast(cherrypy.session.get('username'), cherrypy.session.get('password'), pubmessage, cherrypy.session.get('loginRecord'), cherrypy.session.get('privKey'), url)

                if (broadcast['response'] == 'ok'):
                    print("SUCCESS")
                else:
                    raise TypeError

            except (urllib.error.URLError, TimeoutError, KeyError, TypeError, socket.timeout):
                print("FAILED TO SEND")

        raise cherrypy.HTTPRedirect('/')


    @cherrypy.expose
    def sendPrivatemessage(self, user=None, privmessage=None):
        """endpoint for sending a private messages, checks if the user is online and will attempt to send to their registerd connection_address,
        if they are not online it will send to all active addresses that respond to a ping_check using the users last used pubkey"""

        #check to see if the user is online
        findUser = getUser(cherrypy.session.get('username'), cherrypy.session.get('password'), user)

        #User is offline send message to all avaiable clients.
        if (findUser == -1):
            print('USER NOT ONLINE SENDING TO ALL AVAILABLE CLIENTS')

            #grab offline user data from list of discovered users.
            connect = sqlite3.connect("userdata.db")
            cursor = connect.cursor()

            cursor.execute("select username, pubkey from discoveredUsers where username =?", [user])
            row = cursor.fetchall()

            connect.commit()
            connect.close()

            #if user exists in the database, attempt to send the message using their previous public key.
            if (len(row) > 0):
                targetPubkey = row[0][1]

                global activeAddresses

                for address in activeAddresses:

                    print("SENDING TO: "+address)
                    targetUser = {
                        'username':'%s' % user,
                        'connection_address': '%s' % address,
                        'incoming_pubkey':'%s' % targetPubkey
                    }

                    try:
                        sendPrivate = privMessage(cherrypy.session.get('username'), cherrypy.session.get('password'), privmessage, cherrypy.session.get('loginRecord'), targetUser, cherrypy.session.get('privKey'))

                        if (sendPrivate['response'] == 'ok'):
                            print("SUCCESS")
                        else:
                            raise TypeError

                    except (urllib.error.URLError, TimeoutError, KeyError, TypeError):
                        print("FAILED TO SEND")
            else:
                print("FAILED TO SEND")

        #User is online send to specified connection address.
        else:

            try:
                print("SENDING TO: "+findUser['connection_address'])
                sendPrivate = privMessage(cherrypy.session.get('username'), cherrypy.session.get('password'), privmessage, cherrypy.session.get('loginRecord'), findUser, cherrypy.session.get('privKey'))
            
                if (sendPrivate['response'] == 'ok'):
                    print("SUCCESS")
                else:
                    raise TypeError

            except (urllib.error.URLError, TimeoutError, KeyError, TypeError):
                 print("FAILED TO SEND")


        raise cherrypy.HTTPRedirect('/')


    @cherrypy.expose
    def signin(self, username=None, password=None, secret=None):
        """check user grab private data from the login-server, attempt to log the user in, if attempt fails redirect to /login with bad_attempt=1"""

        privateDataPacket = getPrivateData(username, password)
        userData = authoriseUserLogin(username, password, secret, privateDataPacket)

        if (userData['error'] == 0):
            cherrypy.session['username'] = username
            cherrypy.session['password'] = password
            cherrypy.session['secret'] = secret
            cherrypy.session['pubKey'] = userData['publicKey']
            cherrypy.session['privKey'] = userData['privateKey']
            cherrypy.session['loginRecord'] = getLoginRecord(username, password)
            cherrypy.session['blockedPubkeys'] = userData['blocked_pubkeys']
            cherrypy.session['blockedUsernames'] = userData['blocked_usernames']
            cherrypy.session['blockedWords'] = userData['blocked_words']
            cherrypy.session['blockedMessageSig'] = userData['blocked_message_signatures']
            cherrypy.session['favMessageSig'] = userData['favourite_message_signatures']
            cherrypy.session['friends_usernames'] = userData['friends_usernames']
			
            #grab the users last recorded login time on this client.
            connect = sqlite3.connect("userdata.db")
            cursor = connect.cursor()

            cursor.execute("select lastlogin from discoveredUsers where username=?", [username])
            lastlogin = cursor.fetchall()

            connect.commit()
            connect.close()
			
            #grab active addresses, used to get any new messages, clientAddress is the connection_address of this web_app.
            global activeAddresses
            global clientAddress
            userData = listUsers(username, password)
            users = userData['users']
            activeAddresses = getConnectedWebapps(users, clientAddress, username, password)
			
            #get any new messages from connected web-apps since this user was last online
            print("USER: "+username+" LOGGED IN, LAST LOGGED OUT: "+str(lastlogin))
            getNewMessages(users, username, password, lastlogin[0])

            raise cherrypy.HTTPRedirect('/')
        else:
            raise cherrypy.HTTPRedirect('/login?bad_attempt=1')


    @cherrypy.expose
    def signout(self):
        """Logs the current user out, expires their session, reports them as 'offline' and updates their lastlogin field in the userdata database"""
        username = cherrypy.session.get('username')
        password = cherrypy.session.get('password')
		
        if username is None:
            pass
        else:
            

            #report the user as offline.
            global clientAddress
            logout = reportUser(cherrypy.session['pubKey'], username=username, password=password, connectionAddress=clientAddress, status='offline')
			
            #update users lastlogin field in the database to the current time.
            connect = sqlite3.connect("userdata.db")
            cursor = connect.cursor()

            cursor.execute("""UPDATE discoveredUsers SET lastlogin=? WHERE username=?""", (time.time(), username))

            connect.commit()
            connect.close()
			
            cherrypy.lib.sessions.expire()


        raise cherrypy.HTTPRedirect('/')

class ApiApp(object):

    @cherrypy.expose
    def rx_broadcast(self):
        """recieve public broadcasts: try to get message parameters from the packet and store them in the database, return error if 
        the packet is incorrectly formatted"""
    
        #Get the sent packet.
        dataPacket = cherrypy.request.body.read(int(cherrypy.request.headers['Content-Length']))
        dataPacketDecoded = dataPacket.decode('utf-8')
        publicBroadcast_json = json.loads(dataPacketDecoded)

        respond = {
            'response':'ok'
        }

        #attempt to pull parameters from the packet and insert into the database.
        try:
            message = publicBroadcast_json['message']
            if (message.find('!Meta') == -1):
                loginRecord = publicBroadcast_json['loginserver_record']
                time_Sent = publicBroadcast_json['sender_created_at']
                signature = publicBroadcast_json['signature']

                connect = sqlite3.connect("broadcasts.db")
                cursor = connect.cursor()

                cursor.execute("""insert into publicMessages (record, message, sendTime, signature) values (?,?,?,?)""", (loginRecord, message, float(time_Sent), signature))

                connect.commit()
                connect.close()
            else:
                message_list = message.split(':')

                metaType = message_list[1]
                    
     
            print("RECEIVED: "+publicBroadcast_json['message'])

        except KeyError:
            respond['response'] = 'error'
            respond['message'] = 'missing one or more required fields in packet.'
        except (TypeError, ValueError):
            respond['response'] = 'error'
            respond['message'] = 'unexpected data, packet is malformed.'

        return json.dumps(respond)


    @cherrypy.expose
    def rx_privatemessage(self):
        """recieve private messages: try to get message parameters from the packet and store them in the database, return error if 
        the packet is incorrectly formatted"""

        #Get sent packet
        dataPacket = cherrypy.request.body.read(int(cherrypy.request.headers['Content-Length']))
        dataPacketDecoded = dataPacket.decode('utf-8')
        privateMessage_json = json.loads(dataPacketDecoded)

        respond = {
            'response':'ok'
        }

        #attempt to add message to database.
        try:
            loginRecord = privateMessage_json['loginserver_record']
            targetPubKey = privateMessage_json['target_pubkey']
            targetUsername = privateMessage_json['target_username']
            encryptedMessage = privateMessage_json['encrypted_message']
            time_Sent = privateMessage_json['sender_created_at']
            signature = privateMessage_json['signature']

            connect = sqlite3.connect("broadcasts.db")
            cursor = connect.cursor()

            cursor.execute("""insert into privateMessages (record, targetPubkey, targetUsername, encryptedMessage, receivedTime, signature) values (?,?,?,?,?,?)""",(loginRecord, targetPubKey, targetUsername, encryptedMessage, float(time_Sent), signature))

            connect.commit()
            connect.close()

        except KeyError:
            respond['response'] = 'error'
            respond['message'] = 'missing one or more required fields in packet.'

        except (TypeError, ValueError):
            respond['response'] = 'error'
            respond['message'] = 'unexpected data, packet is malformed.'


        return json.dumps(respond)

 
    @cherrypy.expose
    def ping_check(self):
        """report that this client is currently active"""

        dataPacket = cherrypy.request.body.read(int(cherrypy.request.headers['Content-Length']))
        dataPacketDecoded = dataPacket.decode('utf-8')
        JSON_object = json.loads(dataPacketDecoded)

        currentTime = time.time()
        activeUsers = []

        respond = {
            'response':'ok',
            'my_time':'%s' % currentTime,
            'my_active_usernames':'%s' % activeUsers
        }

        return json.dumps(respond)


    @cherrypy.expose
    def checkmessages(self):
        """check for messages in database tables that are newer than specified timestamp, return as a list"""

        dataPacket = cherrypy.request.body.read(int(cherrypy.request.headers['Content-Length']))
        dataPacketDecoded = dataPacket.decode('utf-8')
        JSON_object = json.loads(dataPacketDecoded)

        #try to get the input timestamp, if the packet is not formatted correctly return an error response.
        try:
            inputTimeStamp = float(JSON_object['since'])

        except KeyError:
            respond['response'] = 'error'
            respond['message'] = 'missing one or more required fields in packet.'

            return json.dumps(respond)

        except (TypeError, ValueError): 
            respond['response'] = 'error'
            respond['message'] = 'unexpected data, packet is malformed.'

            return json.dumps(respond)
            

        publicBroadcasts = []
        privateMessages = []

        #Grab all messages from the database.
        connect = sqlite3.connect("broadcasts.db")
        cursor = connect.cursor()

        cursor.execute("select record, message, sendTime, signature from publicMessages")
        publicRows = cursor.fetchall()
        cursor.execute("select record, targetPubkey, targetUsername, encryptedMessage, receivedTime, signature from privateMessages")
        privateRows = cursor.fetchall()

        connect.commit()
        connect.close()

        #add public broadcasts to the return list if they are newer than the given timestamp.
        for row in publicRows:
            pubtimestamp = float(row[2])

            if (pubtimestamp >= inputTimeStamp):

                payload = {
                    'loginserver_record':'%s' % row[0],
                    'message':'%s' % row[1],
                    'sender_created_at':'%s' % row[2],
                    'signature': '%s' % row[3]
                }

                publicBroadcasts.append(payload)

        #add private messages to the return list if they are newer than the given timestamp.
        for row in privateRows:
            privtimestamp = float(row[4])
           
            if (privtimestamp >= inputTimeStamp):

                payload = {
                    'loginserver_record':'%s' % row[0],
                    'target_pubkey':'%s' % row[1],
                    'target_username':'%s' % row[2],
                    'encrypted_message':'%s' % row[3],
                    'sender_created_at':'%s' % row[4],
                    'signature': '%s' % row[5]
                }

                privateMessages.append(payload)

        #construct the reponse packet for a successful search.
        respond = {
            'response':'ok',
            'broadcasts':publicBroadcasts,
            'private_messages':privateMessages
        }

        return json.dumps(respond).encode('utf-8')

####################################
### BackEnd Functions Below Here ###
####################################

def discoverUsers(users):
    """add currently online users to database, update status of existing users"""

    discoverUsernames = []
    currentTime = time.time()

    connect = sqlite3.connect("userdata.db")
    cursor = connect.cursor()

    #grab list of discovered users
    cursor.execute("select username from discoveredUsers")
    rows = cursor.fetchall()

    #for each online user attempt to add them to the discoveredUsers database
    for user in users:
        discoverUsername = user['username']
        pubkey = user['incoming_pubkey']
        status = user['status']

        discoverUsernames.append(discoverUsername)
        exists = False

        #check to see if user is already discovered, if they are update their status and pubkey
        for row in rows:
            dbUserName = row[0]
                         
            if (discoverUsername == dbUserName):
                exists = True
                cursor.execute("""UPDATE discoveredUsers SET pubkey =?, status =? WHERE username =?""", (pubkey, status, discoverUsername))

        #if does not exist in database add user data to database
        if (exists == False):
            print("DISCOVERED: "+discoverUsername)
            cursor.execute("""insert into discoveredUsers (username, pubkey, status, lastlogin) values (?,?,?,?)"""(discoverUsername, pubkey, status, str(currentTime)))
 
    
    #check to see if any users in the database are not online, update status to offline
    for row in rows:
        dbUserName = row[0]
        if not (dbUserName in discoverUsernames):
            cursor.execute("""UPDATE discoveredUsers SET status = 'offline' WHERE username =?""", [dbUserName])

    
    connect.commit()
    connect.close()


def getNewMessages(users, username, password, lastCheck):
    """call /checkmessages on all active clients and add any new messages to their respective databases."""

    global activeAddresses

    for address in activeAddresses:
        print("GETTING DATA FROM: "+address)
        url = url = "http://"+address+"/api/checkmessages"
 
        payload = {
            'since':'%s' % lastCheck
        }

        json_string = json.dumps(payload)
        json_payload = json_string.encode('utf-8')

        #attempt to get get new data from the address, loop through received messages and add each one to the database if it is not already present in the database.
        try:
            JSON_object = serverRequest(url, data=json_payload, authenticate=True, username=username, password=password)

            if (JSON_object['response'] == 'ok'):

                publicMessages_list = JSON_object['broadcasts']
                privateMessages_list = JSON_object['private_messages']
                
                connect = sqlite3.connect("broadcasts.db")
                cursor = connect.cursor()

                #loop through any received new publicMessages, add them to the database.
                for message in publicMessages_list:

                    #list is empty if element has no characters: do not attempt to decode into json.
                    if (len(message) > 0):
                        
                        loginRecord = message['loginserver_record']
                        publicMessage = message['message']
                        time_Sent = message['sender_created_at']
                        signature = message['signature']

                        #check if the message signature exists in publicMessages
                        cursor.execute("select signature from publicMessages")
                        rows = cursor.fetchall()
                        exists = False

                        for row in rows:
                            dbSignature = row[0]
                         
                            if (signature == dbSignature):
                                exists = True

                        try:
                            #add message to the database if it does not exist already.
                            if (exists == False):
                                print("ADDING BROADCAST: "+publicMessage)
                                cursor.execute("""insert into publicMessages (record, message, sendTime, signature) values (?,?,?,?)""", (loginRecord, publicMessage, float(time_Sent), signature))
                        except ValueError:
                            pass

                    else:
                        print("NO BROADCASTS")


                #loop through any received new privateMessages, add them to the database.
                for message in privateMessages_list:

                    if (len(message) > 0):

                        loginRecord = message['loginserver_record']
                        targetPubKey = message['target_pubkey']
                        targetUsername = message['target_username']
                        encryptedMessage = message['encrypted_message']
                        time_Sent = message['sender_created_at']
                        signature = message['signature']

                        #check if the message signature exists in privateMessages
                        cursor.execute("select signature from privateMessages")
                        rows = cursor.fetchall()
                        exists = False

                        for row in rows:
                            dbSignature = row[0]

                            if (signature == dbSignature):
                                exists = True
                            
                        try:
                            #add message to the database if it does not exist already.
                            if (exists == False):
                                print("ADDING MESSAGE TO: "+targetUsername)
                                cursor.execute("""insert into privateMessages (record, targetPubkey, targetUsername, encryptedMessage, receivedTime, signature) values (?,?,?,?,?,?)""", (loginRecord, targetPubKey, targetUsername, encryptedMessage, time_Sent, signature))

                        except ValueError:
                            pass
                        

                    else:
                        print("NO MESSAGES")


                connect.commit()
                connect.close()

            else:
                raise TypeError

        except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, KeyError, TypeError, json.decoder.JSONDecodeError, AttributeError, socket.timeout) as error:
            print("NO DATA OR FAILED TO RETRIEVE")

        
def getConnectedWebapps(users, username, password, clientAddress):
    """based on a list of online users, ping their webapp connection address and if it is online add it to a list of online webapps"""
  
    listAddresses = []
    resultsQueue = queue.Queue()
    threads = []
    isRunning = True

    #loop for every online user, start a sepearte thread so can ping all users concurrently: this avoids waiting
    #up to 2 seconds in each loop iteration for a potential address timeout.
    for user in users:
        userAddress = user['connection_address']

        pingThread = threading.Thread(target = pingClient, args = (userAddress, clientAddress, resultsQueue, username, password))
        isRunning = True
        threads.append(pingThread)
        pingThread.start()


    #block while threads are still running.
    while (isRunning):
	
        isRunning = False
        for t in threads:
            if t.is_alive():
                isRunning = True
    

    #loop through the queue and add any addresses that were active to the list.
    while not (resultsQueue.empty()):
        result = resultsQueue.get()
        success = result[0]
        address = result[1]

        if (success == 1 and not (address in listAddresses)):
            print(address+" IS ACTIVE")
            listAddresses.append(address)	


    return listAddresses


def pingClient(address, clientAddress, queue, username, password):
    """ping specified address to determine if the client server is active or not, return 1 if active or return -1 if inactive"""

    url = "http://"+address+"/api/ping_check"
    currentTime = time.time()
    activeUsers = []
 
    payload = {
        'my_time':'%s' % currentTime,
        'my_active_usernames':'%s' % activeUsers,
        'connection_address':'%s' % clientAddress,
        'connection_location': 0
    }

    json_string = json.dumps(payload)
    json_payload = json_string.encode('utf-8')

    #try ping the specified address
    try:
        print("PINGING: "+address)
        JSON_object = serverRequest(url, data=json_payload, username=username, password=password)

        if (JSON_object['response'] == 'ok'):
            queue.put([1, address])
        else:
            queue.put([-1, address])

    #packet is returned incorrectly, connection times out, address has not implemented /ping_check
    except (KeyError, TypeError, urllib.error.URLError, TimeoutError, ConnectionResetError):
        queue.put([-1, address])


def authHeader(username=None, password=None, authenticate=False):
    """Generate a basic auth header with the input username and password"""

    credentials = ('%s:%s' % (username, password))
    b64_credentials = base64.b64encode(credentials.encode('ascii'))
    
    header = {
        'Authorization': 'Basic %s' % b64_credentials.decode('ascii'),
        'Content-Type' : 'application/json; charset=utf-8'
    }

    return header


def getUser(yourUsername, yourPassword, userToFind):
    """find data for a specified username, if user is not online return -1"""

    userData = listUsers(yourUsername, yourPassword)
    users = userData['users']
        
    for user in users:
        if (user['username'] == userToFind):
            return user


    return -1


def pubBroadcast(username, password, message, record, privateKey, url):
    """broadcast a public message to input url"""

    currentTime = '%s' % time.time();

    sigMessage = '{}{}{}'.format(record, message, currentTime)
    sig = privateKey.sign(bytes(sigMessage, 'utf-8'), encoder=nacl.encoding.HexEncoder)
    signature_str = sig.signature.decode('utf-8')

    payload = {
        'loginserver_record':'%s' % record,
        'message':'%s' % message,
        'sender_created_at':'%s' % currentTime,
        'signature': '%s' % signature_str
    }

    json_string = json.dumps(payload)
    json_payload = json_string.encode('utf-8')

    JSON_object = serverRequest(url, data=json_payload, authenticate=True, username=username, password=password)

    return JSON_object


def privMessage(username, password, message, record, targetUser, privateKey):
    """send a message to a specified address"""

    message_bytes = bytes(message, 'utf-8')
    targetUsername = targetUser['username']
    targetAddress = targetUser['connection_address']

    url = "http://"+targetAddress+"/api/rx_privatemessage"
    currentTime = '%s' % time.time();

    targetPublicKey_hexStr = targetUser['incoming_pubkey']
    targetPublicKey_hex = bytes(targetPublicKey_hexStr, 'utf-8')
    targetPublicKey = nacl.signing.VerifyKey(targetPublicKey_hex, encoder=nacl.encoding.HexEncoder)
    targetPublicKeyCurve = targetPublicKey.to_curve25519_public_key()

    sealed_box = nacl.public.SealedBox(targetPublicKeyCurve)
    encryptedMessage_bytes = sealed_box.encrypt(message_bytes, encoder=nacl.encoding.HexEncoder)
    encryptedMessage = encryptedMessage_bytes.decode('utf-8')

    #create the signature.
    sigMessage = '{}{}{}{}{}'.format(record, targetPublicKey_hexStr, targetUsername, encryptedMessage, currentTime)
    sig = privateKey.sign(bytes(sigMessage, 'utf-8'), encoder=nacl.encoding.HexEncoder)
    signature_str = sig.signature.decode('utf-8')

    payload = {
        'loginserver_record':'%s' % record,
        'target_pubkey':'%s' % targetPublicKey_hexStr,
        'target_username':'%s' % targetUsername,
        'encrypted_message':'%s' % encryptedMessage,
        'sender_created_at':'%s' % currentTime,
        'signature': '%s' % signature_str
    }

    json_string = json.dumps(payload)
    json_payload = json_string.encode('utf-8')

    JSON_object = serverRequest(url, data=json_payload, authenticate=True, username=username, password=password)

    return JSON_object


def addPubKey(username, password, privateKey, publicKey):
    """add a public key to the users login server privatedata"""

    url = "http://cs302.kiwi.land/api/add_pubkey"

    publicKey_hex = publicKey.encode(encoder=nacl.encoding.HexEncoder)
    publicKey_hexStr = publicKey_hex.decode('utf-8')

    sigMessage = bytes(publicKey_hexStr + username, 'utf-8')
    signature = privateKey.sign(sigMessage, encoder=nacl.encoding.HexEncoder)
    signature_str = signature.signature.decode('utf-8')

    payload = {
        'username':'%s' % username,
        'signature':'%s' % signature_str,
        'pubkey':'%s' % publicKey_hexStr
    }

    json_string = json.dumps(payload)
    json_payload = json_string.encode('utf-8')

    JSON_object = serverRequest(url, data=json_payload, authenticate=True, username=username, password=password)

    return JSON_object['loginserver_record']
	

def pingServer(publicKey, privateKey, username, password):
    """ping the server, confirms pubkey/privkey combination"""
	
    url = "http://cs302.kiwi.land/api/ping"
	
    publicKey_hex = publicKey.encode(encoder=nacl.encoding.HexEncoder)
    publicKey_hexStr = publicKey_hex.decode('utf-8')
	
    sigMessage = bytes(publicKey_hexStr, 'utf-8')
    sig = privateKey.sign(sigMessage, encoder=nacl.encoding.HexEncoder)
    signature_str = sig.signature.decode('utf-8')
	
    payload = {
        'pubkey': '%s' % publicKey_hexStr,
        'signature': '%s' % signature_str
    }
	
    json_string = json.dumps(payload)
    json_payload = json_string.encode('utf-8')
	
    return serverRequest(url, data=json_payload, authenticate=True, username=username, password=password)
    

def listUsers(username, password):
    """grab a list of all users and their data from the login server"""

    url = "http://cs302.kiwi.land/api/list_users"

    return serverRequest(url, authenticate=True, username=username, password=password)
	
	
def reportUser(publicKey, username, password, connectionAddress, status='online'):
    url = "http://cs302.kiwi.land/api/report"
	
    publicKey_hex = publicKey.encode(encoder=nacl.encoding.HexEncoder)
    publicKey_hexStr = publicKey_hex.decode('utf-8')
	
    payload = {
        'connection_address': connectionAddress,
        'connection_location': 0,
        'incoming_pubkey': '%s' % publicKey_hexStr,
        'status': '%s' % status
    }
	
    json_string = json.dumps(payload)
    json_payload = json_string.encode('utf-8')
	
    return serverRequest(url, data=json_payload, authenticate=True, username=username, password=password)


def authoriseUserLogin(username, password, secret, privateDataPacket):
    """create private/public keys if there is no private data, then encrypt using password and send to server.
    if there is private data, decrypt then get the private key and derive the public key."""

    userInfo = {
        'error': 1,
        'privateKey':'null',
        'publicKey':'null'
    }

    try:
        #Decrypt private key and derive public key if there is privateData.
        if (privateDataPacket['response'] == 'ok'):
        
            privateDataEncrypted64 = privateDataPacket['privatedata']
            privateDataEncrypted = base64.b64decode(privateDataEncrypted64)
        
            #derive the secret box and decrypt the data and convert the data into a JSON, if decryption fails return an error.
            try:
                secret_box = getSecretBox(secret)
                privateData = secret_box.decrypt(privateDataEncrypted)
                privateDataDecoded = privateData.decode('utf-8')
                privateDataJSON = json.loads(privateDataDecoded)
            except nacl.exceptions.CryptoError:
                return userInfo

            #Convert private key hexStr back into a signing_key type, then derive the public key.
            privateKey_hexStr = privateDataJSON['prikeys'][0]
            privateKey_hex = bytes(privateKey_hexStr, 'utf-8')
            privateKey = nacl.signing.SigningKey(privateKey_hex, encoder=nacl.encoding.HexEncoder)
            publicKey = privateKey.verify_key

            blockedPub = privateDataJSON['blocked_pubkeys']
            blockedUsers = privateDataJSON['blocked_usernames']
            blockedWords = privateDataJSON['blocked_words']
            blockedMessageSig = privateDataJSON['blocked_message_signatures']
            favMessageSig = privateDataJSON['favourite_message_signatures']
            friends = privateDataJSON['friends_usernames']

		
            #check the key Pair against the login server using /ping.
            checkKeys = pingServer(publicKey, privateKey, username=username, password=password)
            global clientAddress
		
            if (checkKeys['authentication'] == 'basic'):
			
                #report the user as online.
                login = reportUser(publicKey, username=username, password=password, connectionAddress=clientAddress, status='online')
			
                #if 'ok' response received successful login.
                if (login['response'] == 'ok'):
                    userInfo['error'] = 0
                    userInfo['privateKey'] = privateKey
                    userInfo['publicKey'] = publicKey
                    userInfo['blocked_pubkeys'] = blockedPub
                    userInfo['blocked_usernames'] = blockedUsers
                    userInfo['blocked_words'] = blockedWords
                    userInfo['blocked_message_signatures'] = blockedMessageSig
                    userInfo['favourite_message_signatures'] = favMessageSig
                    userInfo['friends_usernames'] = friends

        
        #Create a new key pair and add it to the users private data if there is no existing data.
        elif (privateDataPacket['response'] == 'no privatedata available'):
        
            #create the new key pair.
            privateKey = nacl.signing.SigningKey.generate()
            publicKey = privateKey.verify_key

            #add the new pubKey to the account and update the private key in privateData.
            record = addPubKey(username, password, privateKey, publicKey)
            error = sendPrivateData(privateKey, record, username, password, secret)
        
            if (error['response'] == 'ok'):
			
                #report the user as online.
                login = reportUser(publicKey, username=username, connectionAddress=clientAddress, password=password)
			
                #if 'ok' response received successful login.
                if (login['response'] == 'ok'):
                    userInfo['error'] = 0
                    userInfo['privateKey'] = privateKey
                    userInfo['publicKey'] = publicKey
                    userInfo['blocked_pubkeys'] = []
                    userInfo['blocked_usernames'] = []
                    userInfo['blocked_words'] = []
                    userInfo['blocked_message_signatures'] = []
                    userInfo['favourite_message_signatures'] = []
                    userInfo['friends_usernames'] = []
    
    except (TypeError, KeyError):
        pass

    return userInfo


def getPrivateData(username, password):
    """get privatedata for specified credentials"""

    url = "http://cs302.kiwi.land/api/get_privatedata"

    return serverRequest(url, authenticate=True, username=username, password=password)


def sendPrivateData(privateKey, record, username, password, secret, blockedPub=[], blockedUser=[], blockedMessage=[], blockedWords=[], favouriteMessage=[], friends=[]):
    """Format input data into JSON bytes, encrypt the data with the users secret box (generated from 
    their secret password) then send to the login server to be saved"""

    url = "http://cs302.kiwi.land/api/add_privatedata"
    currentTime = '%s' % time.time();
	
    privateKey_hex = privateKey.encode(encoder=nacl.encoding.HexEncoder)
    privateKey_hexStr = privateKey_hex.decode('utf-8')

    privateKeys = [privateKey_hexStr]
    friendUsers = []

    privateData = {
        'prikeys': privateKeys,
        'blocked_pubkeys': blockedPub,
        'blocked_usernames': blockedUser,
        'blocked_words': blockedWords,
        'blocked_message_signatures': blockedMessage,
        'favourite_message_signatures': favouriteMessage,
        'friends_usernames': friends
    }
    
    secret_box = getSecretBox(secret)

    #convert privatedata into json bytes format then encrypt using the secret_box.
    privateDataJSON_string = json.dumps(privateData)
    privateDataJSON_bytes = bytes(privateDataJSON_string, 'utf-8')
    encryptedMessage_bytes = secret_box.encrypt(privateDataJSON_bytes)
    b64encryptedMessage = base64.b64encode(encryptedMessage_bytes)

    #create the signature.
    sigMessage = '{}{}{}'.format(b64encryptedMessage.decode('ascii'), record, currentTime)
    sig = privateKey.sign(bytes(sigMessage, 'utf-8'), encoder=nacl.encoding.HexEncoder)
    signature_str = sig.signature.decode('utf-8')

    payload = {
	'privatedata': b64encryptedMessage.decode('ascii'),
        'loginserver_record': '%s' % record,
        'client_saved_at': currentTime,
        'signature': '%s' % signature_str
    }

    json_string = json.dumps(payload)
    json_payload = json_string.encode('utf-8')

    return serverRequest(url, data=json_payload, authenticate=True, username=username, password=password)


def getSecretBox(sPassword):
    """create a secret box for private data encryption using a user specified secret-password"""

    sPassword_bytes = bytes(sPassword, encoding='utf-8')
    
    salt = sPassword*16
    salt = bytes(salt, 'utf-8')
    salt = salt[0:16]
    ops = nacl.pwhash.argon2i.OPSLIMIT_SENSITIVE
    mem = nacl.pwhash.argon2i.MEMLIMIT_SENSITIVE
    symKey = nacl.pwhash.argon2i.kdf(nacl.secret.SecretBox.KEY_SIZE, sPassword_bytes, salt, ops, mem)

    return nacl.secret.SecretBox(symKey)
    

def getLoginRecord(username, password):
    """get the login-servers record using input credentials"""

    url = "http://cs302.kiwi.land/api/get_loginserver_record"

    status = serverRequest(url, authenticate=True, username=username, password=password)

    if (status['response'] == 'ok'):
        return status['loginserver_record']
    else:
        return -1


def serverRequest(url=None, data=None, authenticate=False, username=None, password=None):
    """Send a request to input url with data, authenticate indicates a header should be provided
    in which case the input username and password are used to generate a basic auth header"""

    headers = authHeader(username=username, password=password, authenticate=authenticate)
    req = urllib.request.Request(url, data=data, headers=headers)

    try:
        response = urllib.request.urlopen(req, timeout=2)
        receivedData = response.read() # read the received bytes
        encoding = response.info().get_content_charset('utf-8') #load encoding if possible (default to utf-8)
        response.close()
    except (urllib.error.HTTPError, UnicodeError, socket.timeout) as error:
        return 'bad request'

    JSON_object = json.loads(receivedData.decode(encoding))
    return JSON_object


    

