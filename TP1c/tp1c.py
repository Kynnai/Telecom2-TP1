from socketserver import TCPServer, BaseRequestHandler, ThreadingMixIn
import ssl
import traceback

class SSLServer(TCPServer):

    def __init__(self, serverIP="127.0.0.1", serverPort="443", certFile=None, keyFile=None, protocol=ssl.PROTOCOL_SSLv23):
        self.__set_SSL_Context(certFile, keyFile, protocol)
        super().__init__((serverIP, serverPort), SSLRequestHandler)#We create a TCP server on a specific IP:port of this machine. SSLRequestHandler is the class that will be instanciated everytime a connexion request is made on that IP:port
        print("Server instance created")

    def serve_forever(self):
        print("Listening on " + self.server_address[0] + ":" + str(self.server_address[1]))
        try:
            super().serve_forever()
        except:
            print("Server shutting down")
            super().shutdown()

    def get_request(self):
        newSocket, FromAddr = self.socket.accept()
        print("Connection from " + FromAddr[0])
        connStream = self.context.wrap_socket(newSocket, server_side=True, do_handshake_on_connect=True)
        return (connStream, FromAddr)

    def handle_error(self, request, client_address):
        err_traceback = traceback.format_exc()
        print(err_traceback)

    def __set_SSL_Context(self, certFile, keyFile, protocol):
        self.context = ssl.SSLContext(protocol)
        self.context.load_cert_chain(certfile=certFile, keyfile=keyFile)

class SSLRequestHandler(BaseRequestHandler):

    def setup(self):
        print("setup")

    def handle(self):
        print("SSL Request ready to be handled")
        self.data = self.buildResponse()
        self.request.sendall(self.data)
        request = str(self.request.recv(1024)).split("/")[1].split("?")[1].split("&")
        print(request[0])
        print(request[1].split(" ")[0])

    def buildResponse(self):
        rep = """<html>
<body>
<form action="auth.php">
Username: </br>
<input type="text" name="username">
<br>
Password:</br>
<input type="password" name="password">
<br>
<br>
<input type="submit" value="Send">
</form>
</br>
This is a very secure page, trust us no worries. All you data will be encrypted.
</body>
</html>"""
        return rep.encode("utf-8")

    #given to students
    def finish(self):
        print("Done with connection from " + self.client_address[0])

if __name__ == "__main__":
    certFile="./Certificates/myCert.crt"
    keyFile="./Certificates/myKey.key"
    ip = "172.16.1.5"
    port = 443

    server = SSLServer(serverIP=ip,
            serverPort=port,
            certFile=certFile,
            keyFile=keyFile)
    server.serve_forever()

