import socket
import ssl
import threading
import signal,sys,time
import pathlib
from subprocess import Popen, PIPE

def signal_handler(signal, frame):
    print("\nprogram exiting gracefully")
    sys.exit(0)

#############################################################

contextx = ssl.SSLContext(ssl.PROTOCOL_TLSv1_2)
contextx.verify_mode = ssl.CERT_REQUIRED
contextx.check_hostname = True
contextx.load_default_certs()

# context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
# context.load_cert_chain(certfile="C:\\Users\\HP\\OneDrive\\Desktop\\cert.pem", keyfile="C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\cert.key")


####################################################################

def proxy_thread(client_socket, client_address):
    request = client_socket.recv(8096) 
    #print(request)
  
    sending = request
    request = request.decode("utf-8")
    # print("Orignal Req :\n",request)


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
            port = 80
            webserver = temp[:webserver_pos] 

        else: # specific port 
            port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
            webserver = temp[:port_pos] 

        # if "www" not in webserver:
        #     webserver = "www." + webserver

        print(f"{webserver} {port}")

        # new_req = request[8:]
        # new_req = "GET " + route + " HTTP/1.1\r\n"
        # REQ = request.split('\n')
        # REQ = REQ[1:len(REQ)-3]
        # flag = 1
        # for x in REQ:
        #     if("Host" in x):
        #         flag = 0
        #     new_req = new_req + x + "\n"
        # if(flag):
        #     new_req = new_req + f"Host: {webserver}:{port}"
        # new_req = new_req + "\r\n"
        # new_req = new_req + "\r\n"
        # new_req = new_req + "\r\n"
        # print(new_req)
        # print(f"0th :-a{new_req[0]}a")

        
        # context.wrap_socket(s, server_hostname=webserver)


        # cakey = pathlib.Path(__file__).parent.joinpath("C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\ca.key")
        # cacert = pathlib.Path(__file__).parent.joinpath("C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\ca.crt")
        # certkey = pathlib.Path(__file__).parent.joinpath("C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\cert.key")
        # certdir = pathlib.Path(__file__).parent.joinpath("C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\specific_certs\\")
        # extensionfile = pathlib.Path(__file__).parent.joinpath("C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\extfile.tmp")

        # specific_cert = certdir.joinpath(f"{webserver}.crt")

        
        # if not specific_cert.is_file():
        #     epoch = "%d" % (time.time() * 1000)
        #     extensionfile.write_text("subjectAltName=DNS:%s" % webserver)
        #     p1 = Popen(["C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe", "req", "-new", "-key", certkey, "-subj", "/CN=%s" % webserver, "-addext", "subjectAltName = DNS:%s" % webserver], stdout=PIPE)
        #     p2 = Popen(["C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe", "x509", "-req", "-extfile", extensionfile, "-days", "365", "-CA", cacert, "-CAkey", cakey, "-set_serial", epoch, "-out", specific_cert], stdin=p1.stdout, stderr=PIPE)
        #     p2.communicate()

        # specific_cert = certdir.joinpath(f"{webserver}.crt")

        # context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # context.load_cert_chain(certfile=specific_cert, keyfile=certkey)

        
        reply = "HTTP/1.0 200 Connection established\r\n"
        reply += "Proxy-agent: Jarvis\r\n"
        reply += "\r\n"
        client_socket.sendall(reply.encode())
        # print(sending)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        #s = contextx.wrap_socket(s, server_hostname=webserver)
        s.connect((webserver,port))
        # s.sendall(sending)

        print("Replying")

        #client_socket = context.wrap_socket(client_socket, server_side=True)

        # client_socket.setblocking(0)
        # s.setblocking(0)

        
        # request = client_socket.recv(100000)
        # print(request)
        # sending = request
        # if(len(request) > 0):
        #     request = request.decode("utf-8")
        #     first_line = request.split('\n')[0]
        #     method = first_line.split(' ')[0]
        #     url = first_line.split(' ')[1]
        #     #Then, we find the destination address of the request. Address is a tuple of (destination_ip_address, destination_port_no). We will be receiving data from this address.
        #     http_pos = url.find("://") # find pos of ://
        #     if (http_pos==-1):
        #         temp = url
        #     else:
        #         temp = url[(http_pos+3):] # get the rest of url

        #     port_pos = temp.find(":") # find the port pos (if any)

        #     # find end of web server
        #     #print("temp - ",temp)
        #     webserver_pos = temp.find("/")
        #     #print("webserver_pos - ",webserver_pos)
        #     if webserver_pos == -1:
        #         webserver_pos = len(temp)
        #         route = "/"
        #     else:
        #         route = temp[webserver_pos:]
        #         #print("route - ",route)

        #     webserver = ""
        #     port = -1
        #     if (port_pos==-1 or webserver_pos < port_pos): 

        #         # default port 
        #         port = 80
        #         webserver = temp[:webserver_pos] 

        #     else: # specific port 
        #         port = int((temp[(port_pos+1):])[:webserver_pos-port_pos-1])
        #         webserver = temp[:port_pos] 

        #     # if "www" not in webserver:
        #     #     webserver = "www." + webserver

        #     print(f"{webserver} {port}")

        #     cakey = pathlib.Path(__file__).parent.joinpath("C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\ca.key")
        #     cacert = pathlib.Path(__file__).parent.joinpath("C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\ca.crt")
        #     certkey = pathlib.Path(__file__).parent.joinpath("C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\cert.key")
        #     certdir = pathlib.Path(__file__).parent.joinpath("C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\specific_certs\\")
        #     extensionfile = pathlib.Path(__file__).parent.joinpath("C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\extfile.tmp")

        #     specific_cert = certdir.joinpath(f"{webserver}.crt")

            
        #     if not specific_cert.is_file():
        #         epoch = "%d" % (time.time() * 1000)
        #         extensionfile.write_text("subjectAltName=DNS:%s" % webserver)
        #         p1 = Popen(["C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe", "req", "-new", "-key", certkey, "-subj", "/CN=%s" % webserver, "-addext", "subjectAltName = DNS:%s" % webserver], stdout=PIPE)
        #         p2 = Popen(["C:\\Program Files\\OpenSSL-Win64\\bin\\openssl.exe", "x509", "-req", "-extfile", extensionfile, "-days", "365", "-CA", cacert, "-CAkey", cakey, "-set_serial", epoch, "-out", specific_cert], stdin=p1.stdout, stderr=PIPE)
        #         p2.communicate()

        #     specific_cert = certdir.joinpath(f"{webserver}.crt")

        #     context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        #     context.load_cert_chain(certfile=specific_cert, keyfile=certkey)
        #     # print(request.decode())
        #     s.sendall(sending)
            
        #     time.sleep(1)
        #     result = b''
        #     reply = b''
        # client_socket = context.wrap_socket(client_socket, server_side=True)
        # reply = b''
        # result = s.recv(8096)
        # while len(result) > 0:
        #     reply += result
        #     client_socket.sendall(result)
        #     result = s.recv(8096)

        while True:
            try:
                req = client_socket.recv(8096)
                print(req[:100])
                s.sendall(req)
            except:
                pass
            try:
                res = s.recv(100000)
                client_socket.sendall(res)
            except:
                pass
        
        #
        #print(reply)
        # client_socket.sendall(reply)
            


        # while (len(result) > 0):
        #     print(result)
        #     client_socket.send(result)
        #     result = s.recv(8096)
        
        # print("------------------Recieved : \n",result)
        # time.sleep(2)
        # s.close()
        # time.sleep(2)
        # client_socket.close()


#-----------------------------------------------------------

server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(("localhost", 9999))
server_socket.listen()
print("Listening ...")
while True:
    try:
        signal.signal(signal.SIGINT, signal_handler) 
        (client_socket, client_address) = server_socket.accept()
        # context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        # context.load_cert_chain(certfile="C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\ca.crt", keyfile="C:\\Users\\HP\\OneDrive\\Desktop\\python-websocket-proxy\\certs\\ca.key")
        # client_socket = context.wrap_socket(client_socket, server_side=True)
        print("Connection from - ",client_address)
        d = threading.Thread(name=client_address, 
        target = proxy_thread, args=(client_socket, client_address))
        d.setDaemon(True)
        d.start()
    except KeyboardInterrupt:
        print('interrupted!')