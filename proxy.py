# import socket
# import threading 
# import sys, signal
# import ssl,time

# # context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# # context.load_cert_chain(certfile="C:\\Users\\HP\\OneDrive\\Desktop\\cert.pem", keyfile="C:\\Users\\HP\\OneDrive\\Desktop\\key.pem")


# def signal_handler(signal, frame):
#     print("\nprogram exiting gracefully")
#     sys.exit(0)

# def proxy_thread(conn, client_address):
#     # get the request from browser
#     # conn.sendall('HTTP/1.1 200 Connection Established\r\n\r\n'.encode())
#     # conn = ssl.wrap_socket(conn, keyfile = 'C:\\Users\\HP\\OneDrive\\Desktop\\key.pem', certfile = 'C:\\Users\\HP\\OneDrive\\Desktop\\cert.pem', server_side = True, do_handshake_on_connect = False)
#     # conn.do_handshake()

#     request = conn.recv(8096) 
#     #print(request)
#     request = request.decode("utf-8")
#     # print(type(request))
#     #print(request)
    
    
#     if(len(request) > 0):
#         # parse the first line
#         first_line = request.split('\n')[0]

#         # get url
#         method = first_line.split(' ')[0]
#         url = first_line.split(' ')[1]
#         #Then, we find the destination address of the request. Address is a tuple of (destination_ip_address, destination_port_no). We will be receiving data from this address.
#         http_pos = url.find("://") # find pos of ://
#         if (http_pos==-1):
#             temp = url
#         else:
#             temp = url[(http_pos+3):] # get the rest of url

#         port_pos = temp.find(":") # find the port pos (if any)

#         # find end of web server
#         #print("temp - ",temp)
#         webserver_pos = temp.find("/")
#         #print("webserver_pos - ",webserver_pos)
#         if webserver_pos == -1:
#             webserver_pos = len(temp)
#             route = "/"
#         else:
#             route = temp[webserver_pos:]
#             #print("route - ",route)

#         webserver = ""
#         port = -1
#         if (port_pos==-1 or webserver_pos < port_pos): 

#             # default port 
#             port = 80 
#             webserver = temp[:webserver_pos] 

#         else: # specific port 
#             port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
#             webserver = temp[:port_pos] 

#         print(f"{webserver} {port}")

#         new_req = request[8:]
#         new_req = "GET " + route + " HTTP/1.1\r\n"
#         REQ = request.split('\n')
#         REQ = REQ[1:len(REQ)-3]
#         flag = 1
#         for x in REQ:
#             if("Host" in x):
#                 flag = 0
#             new_req = new_req + x + "\n"
#         if(flag):
#             new_req = new_req + f"HOST: {webserver}"
#         new_req = new_req + "\r\n"
#         new_req = new_req + "\r\n"
#         new_req = new_req + "\r\n"
#         print(new_req)
#         #print(new_req.encode())
#         # s = ssl.wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), ssl_version=ssl.PROTOCOL_TLSv1_1)
#         # s = ssl.create_default_context().wrap_socket(socket.socket(socket.AF_INET, socket.SOCK_STREAM), server_hostname=webserver)

        

#         s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         s.connect((webserver, port))
#         #s = context.wrap_socket(s, server_side = True, do_handshake_on_connect = False)
#         #s.do_handshake()
#         #s.settimeout(config['CONNECTION_TIMEOUT'])
#         s.sendall(new_req.encode())
#         print("HERE")



#         # ssl_context = ssl.create_default_context()
#         # ssl_context.check_hostname = False
#         # ssl_context.verify_mode = ssl.CERT_NONE
#         client_socket = conn
#         # Wrap the client socket with the SSL context
#         # client_socket = ssl_context.wrap_socket(conn, server_hostname=None)
#         # client_socket = ssl.create_default_context().wrap_socket(conn, server_hostname=client_address[0])
#         while 1:
#         # receive data from web server
#             data = s.recv(8096)
#             print("data ----------  ",data)
#             if (len(data) > 0):
#                 client_socket.send(data) # send to browser/client
#             else:
#                 break
#         #client_socket.close()
    


# signal.signal(signal.SIGINT, signal_handler) 
# # Create a TCP socket

# serverSocket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)


# # Re-use the socket
# serverSocket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
# #serverSocket = context.wrap_socket(serverSocket, server_side=True)
# # bind the socket to a public host, and a port   
# print(socket.gethostname())
# serverSocket.bind(("192.168.1.5", 12345))

# serverSocket.listen(10) # become a server socket

# __clients = {}

# while True:
#     try:
#         # Establish the connection
#         signal.signal(signal.SIGINT, signal_handler) 
#         print("Listening...")
#         (clientSocket, client_address) = serverSocket.accept() 
#         print(client_address)
#         # print(client_address)
#         # secure_socket = context.wrap_socket(clientSocket, server_side = True, do_handshake_on_connect = False)
#         # secure_socket.do_handshake()
#         # secure_socket = context.wrap_socket(clientSocket, server_side=True)
#         # secure_socket.do_handshake()
#         print(client_address)
#         d = threading.Thread(name=client_address, 
#         target = proxy_thread, args=(clientSocket, client_address))
#         d.setDaemon(True)
#         d.start()
#     except KeyboardInterrupt:
#         # sys.exit(0)
#         print('interrupted!')


# # import socket

# # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# # s.bind((socket.gethostname(), 1234))
# # s.listen(5)

# # while True:
# #     # now our endpoint knows about the OTHER endpoint.
# #     clientsocket, address = s.accept()
# #     print(f"Connection from {address} has been established.")
# #     clientsocket.send(bytes("Hey there!!!","utf-8"))
# #     clientsocket.close()
































# import socket
# import ssl

# context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
# context.load_verify_locations(cafile="C:\\Users\\HP\\OneDrive\\Desktop\\cert.pem")
# context.check_hostname = True
# context.verify_mode = ssl.CERT_REQUIRED

# server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# server_socket.connect(("192.168.1.5", 12345))

# secure_socket = context.wrap_socket(server_socket, server_hostname="Sahil")
# Continue processing secure_socket as needed


import socket
import ssl
import threading
import signal,sys,time

def signal_handler(signal, frame):
    print("\nprogram exiting gracefully")
    sys.exit(0)

#############################################################

context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
context.verify_mode = ssl.CERT_REQUIRED
context.check_hostname = True
context.load_default_certs()

####################################################################

def proxy_thread(client_socket, client_address):
    request = client_socket.recv(8096) 
    #print(request)
    sending = request
    request = request.decode("utf-8")
    print("Orignal Req :\n",request)


    if(len(request) > 0):
        first_line = request.split('\n')[0]
        method = first_line.split(' ')[0]
        url = first_line.split(' ')[1]
        #Then, we find the destination address of the request. Address is a tuple of (destination_ip_address, destination_port_no). We will be receiving data from this address.
        http_pos = url.find("://") # find pos of ://
        if (http_pos==-1):
            temp = url
        else:
            temp = url[(http_pos+3):] # get the rest of url

        port_pos = temp.find(":") # find the port pos (if any)

        # find end of web server
        #print("temp - ",temp)
        webserver_pos = temp.find("/")
        #print("webserver_pos - ",webserver_pos)
        if webserver_pos == -1:
            webserver_pos = len(temp)
            route = "/"
        else:
            route = temp[webserver_pos:]
            #print("route - ",route)

        webserver = ""
        port = -1
        if (port_pos==-1 or webserver_pos < port_pos): 

            # default port 
            port = 443
            webserver = temp[:webserver_pos] 

        else: # specific port 
            port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
            webserver = temp[:port_pos] 

        # if "www" not in webserver:
        #     webserver = "www." + webserver

        print(f"{webserver} {port}")

        new_req = request[8:]
        new_req = "GET " + route + " HTTP/1.1\r\n"
        REQ = request.split('\n')
        REQ = REQ[1:len(REQ)-3]
        flag = 1
        for x in REQ:
            if("Host" in x):
                flag = 0
            new_req = new_req + x + "\n"
        if(flag):
            new_req = new_req + f"Host: {webserver}:{port}"
        new_req = new_req + "\r\n"
        new_req = new_req + "\r\n"
        new_req = new_req + "\r\n"
        print(new_req)
        # print(f"0th :-a{new_req[0]}a")

        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s = context.wrap_socket(s, server_hostname=webserver)

        

        s.connect((webserver,port))
        s.send(new_req.encode())
        result = b''
        result = s.recv(8096)

        while (len(result) > 0):
            print(result)
            client_socket.send(result)
            result = s.recv(8096)
        
        print("------------------Recieved : \n",result)
        time.sleep(2)
        s.close()
        time.sleep(2)
        client_socket.close()


#-----------------------------------------------------------

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("192.168.1.5", 12345))
server_socket.listen()
print("Listening ...")
while True:
    try:
        signal.signal(signal.SIGINT, signal_handler) 
        (client_socket, client_address) = server_socket.accept()
        print("Connection from - ",client_address)
        d = threading.Thread(name=client_address, 
        target = proxy_thread, args=(client_socket, client_address))
        d.setDaemon(True)
        d.start()
    except KeyboardInterrupt:
        print('interrupted!')





######################################################################

# context = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
# context.verify_mode = ssl.CERT_REQUIRED
# context.check_hostname = True
# context.load_default_certs()




# server = "www.google.com"
# port = 443


# s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# s = context.wrap_socket(s, server_hostname=server)

# request = "GET / HTTP/1.1\nHost: "+server+"\n\n"

# s.connect((server,port))
# s.send(request.encode())
# result = s.recv(4096)

# while (len(result) > 0):
#     print(result)
#     result = s.recv(4096).decode()

# s.close()
