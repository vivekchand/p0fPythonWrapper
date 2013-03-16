import p0fmod
import socket
import sys

# Create a UDS socket
sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
api_resp_sz=300
# Connect the socket to the port where the server is listening
server_address = sys.argv[1] 
#print >>sys.stderr, 'connecting to %s' % server_address

try:
    sock.connect(server_address)
except socket.error, msg:
    print >>sys.stderr, msg
    sys.exit(1)
try:
    message = p0fmod.mk_query(sys.argv[2])
    sock.sendall(message)   

    dat = sock.recv(api_resp_sz)
    data = dat.strip()
    p0fmod.ck_response(data)
	
finally:
    sock.close()
