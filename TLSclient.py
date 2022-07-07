import socket
from Cryptodome.Hash import SHA256
from Cryptodome.Cipher import AES

MSG_DELIMITER = "\r\n"

HOST = "netsec.unipr.it"
PORT = 7022
TIMEOUT = 10
delimiter = "\r\n"

def unpad(padded : bytes) -> bytes:
	size= len(padded)
	padlen= padded[size-1]
	return padded[:size-padlen]

def add_padding(cleartext):
    length = 16 - (len(cleartext) % 16)
    cleartext += bytes([length])*length
    return cleartext
    
def error_checking(data, array_data):
    if array_data[0] == "ERROR":
        print("\u2708 An error occurred during the handshake!")
        print(data)
        s.close()
        exit(-1)

def receiveTCPData(s):
    buffer=""
    while True:
        received = s.recv(1).decode("utf-8")
        buffer += received

        if buffer.endswith(delimiter):
            return buffer


#initialization
g = 2
p = 171718397966129586011229151993178480901904202533705695869569760169920539808075437788747086722975900425740754301098468647941395164593810074170462799608062493021989285837416815548721035874378548121236050948528229416139585571568998066586304075565145536350296006867635076744949977849997684222020336013226588207303
xc= 581653603720443212670038328865006257879554410432796221735023975689267215344537985570480348929339571200971269505146865970287397758935553477713134007735884
print("xc:",xc)
print("\n")
yc = pow(g,xc,p)
print("yc:",yc)

print("\n")
print(f"...Connecting to {HOST}:{PORT}...")
s = socket.create_connection((HOST, PORT), TIMEOUT)
print("\n")
print("\u2705 Succesfully connected")
print("\n")

#sending first message
msg = "HELLO {}\r\n".format(yc)
s.sendall(bytes(msg,encoding="utf-8"))
print("\U0001F4E8 Sent message:\n",bytes(msg,encoding="utf-8"))
print("\n")

#receiving HELLO message from server
data = receiveTCPData(s)
print("\U0001F4E8 Received message:\n",data)
print("\n")
array_data = data.split()
error_checking(data,array_data)
ys = int(array_data[1])
print("ys:",ys)
print("\n")

# compute secret key
print("Computing secret key...\n\n")
dh= pow(ys,xc,p)
print("dh:",dh)
print("\n")
secret_key = dh.to_bytes(128,'big')
print("secret_key:",secret_key.hex())

print("\n")


# receiving CERTIFICATE message from server
data = receiveTCPData(s)
print("\U0001F4E8 Received message:\n",data)
array_data = data.split()
error_checking(data,array_data)
modulus = int(array_data[2])
e = int(array_data[1])
d = pow(e,-1,modulus)
print("e:", e)
print("\n")
print("modulus:", modulus)
print("\n")
print("d:", d)
print("\n")


#certificate validation
print("Certificate validation...\n")
data = receiveTCPData(s)
print("\U0001F4E8 Received message:\n",data)
print("\n")
array_data = data.split()
error_checking(data,array_data)
digital_certificate = int(array_data[1])
print("cert:", digital_certificate)
print("\n")

#calculate hash value with RSA public key {e,N}
hashed_cert = pow(digital_certificate,e,modulus)
print("hashed_certificate_received:", hashed_cert.to_bytes(32,'big').hex())

#computing SHA256(bytes(Yc||Ys)) to verify the received certificate
h = SHA256.new()
hash_key = str(yc) + str(ys)
hash_key = bytes(hash_key, encoding="ASCII")
h.update(hash_key)

print("hashed_certificate_calculated:",h.hexdigest())
print("\n")
if(hashed_cert.to_bytes(32,'big').hex() != h.hexdigest()) :
    print("\u274C Certificate not validated!")
    s.close()
    exit(-1)
else:
    print("\u2705 Certificate succesfully validated!")
    print("\n")



#compute MAC(secretKey||MAC_S)
data = receiveTCPData(s)
print("\U0001F4E8 Received message:\n",data)
print("\n")
array_data = data.split()
error_checking(data,array_data)
print("Computing MAC value...")
print("\n")
mac_value = array_data[1]
print("mac_value:", mac_value)
print("\n")
print("secret_key:",secret_key[-16:].hex().encode())
print("\n")

#computing MAC_C = SHA256(SecretKey||MAC_S).
m = SHA256.new()
m.update(bytes.fromhex(secret_key[-16:].hex()+mac_value))


print("MAC_C:",m.hexdigest())
print("\n")


#send finished message to the server
msg = "FINISHED {}\r\n".format(m.hexdigest())
s.sendall(bytes(msg,encoding="utf-8"))
print("\U0001F4E8 Sent message:\n",bytes(msg,encoding="utf-8"))
print("\n")


#sending data msg to the server
print("\u2705 Handshake successfully completed!")
print("\n")
key = secret_key[-16:]

iv= bytes([0x0]) * 16 # iv=0
encryption_cipher= AES.new(key,AES.MODE_CBC,iv)
decryption_cipher= AES.new(key,AES.MODE_CBC,iv)
message = "Test message"
cleartext = message.encode()
cleartext = add_padding(cleartext)
ciphertext = encryption_cipher.encrypt(cleartext)
print("msg:", message)
print("\n")
print("cipertext:", ciphertext.hex())
print("\n")
#send finished message to the server
msg = "DATA {}\r\n".format( ciphertext.hex())
s.sendall(bytes(msg,encoding="utf-8"))
print("\U0001F4E8 Sent data:\n",msg)


#receiving response data from server
data = receiveTCPData(s)
print("\U0001F4E8 Received data:\n",data)
print("\n")
array_data = data.split()
error_checking(data,array_data)

cleartext = decryption_cipher.decrypt(ciphertext= bytearray.fromhex(array_data[1]))
cleartext = unpad(cleartext)
message = cleartext.decode()
print("Decrypted message:", message)

