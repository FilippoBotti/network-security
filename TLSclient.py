from array import array
import socket
from tkinter import Y
import hashlib
from turtle import clear
from Cryptodome.Hash import SHA256
import hmac
import base64
from Crypto.Cipher import AES

HOST = "netsec.unipr.it"
PORT = 7022
TIMEOUT = 10

g = 2
p = 171718397966129586011229151993178480901904202533705695869569760169920539808075437788747086722975900425740754301098468647941395164593810074170462799608062493021989285837416815548721035874378548121236050948528229416139585571568998066586304075565145536350296006867635076744949977849997684222020336013226588207303
xc= 581653603720443212670038328865006257879554410432796221735023975689267215344537985570480348929339571200971269505146865970287397758935553477713134007735884
print("xc:",xc)
yc = 59503431474414346454541663355228363784447143762293059580768630217024999189387331369173796013956872904010843181272943187119228828469298343869299687804467861488327405020041584093736891526885461645373355485457478357069879698933642848474726291998723103646246946228046726181790155291164018479481498386949906108527
print("yc:",yc)

def unpad(padded : bytes) -> bytes:
	size= len(padded)
	padlen= padded[size-1]
	return padded[:size-padlen]

def client_hello_msg():
    msg = "HELLO {y_c}\r\n"
    return b"HELLO 59503431474414346454541663355228363784447143762293059580768630217024999189387331369173796013956872904010843181272943187119228828469298343869299687804467861488327405020041584093736891526885461645373355485457478357069879698933642848474726291998723103646246946228046726181790155291164018479481498386949906108527\r\n"

def error_checking(data, array_data):
    if array_data[0] == "ERROR":
        print(data)
        s.close()
        exit(-1)

print(f"Connecting to {HOST}:{PORT}")
s = socket.create_connection((HOST, PORT), TIMEOUT)

s.sendall(client_hello_msg())


data = s.recv(1024)
array_data = data.decode("UTF-8").split()
error_checking(data,array_data)
ys = int(array_data[1])
#ys = 40253415771187983233943397873243068057370159192255380223170059969618433495860301736760665908570563902225255992771958133721584083090836304853436823348332842525686172282047961765214813209809650489822458025667780105580039008152635691832601151681957629328114048066202409424212574171314461664496174818987900181144
print("ys:",ys)

# compute secret key
dh= pow(ys,xc,p)
print("dh:",dh)
xs =8884495164705596805131146661467677867275824838347132354168048384922475430766367129122973573006522014142820879150727824441345026083904955023264091880817739
dah = pow(g,(xc*xs),p)
print("dah:", dah)
secret_key = dh.to_bytes(128,'big')
print("secret_key:",secret_key.hex())


# get server response
data = s.recv(1024)
array_data = data.decode("UTF-8").split()
error_checking(data,array_data)
print(array_data)


#certificate validation
digital_certificate = int(array_data[4])
modulus = int(array_data[2])
e = int(array_data[1])
d = pow(e,-1,modulus)
print("e:", e)
print("modulus:", modulus)
print("d:", d)
print("cert:", digital_certificate)

hashed_cert = pow(digital_certificate,e,modulus)
print("hashed_certificate_received:", hashed_cert.to_bytes(32,'big').hex())

h = SHA256.new()
mac_key = str(yc) + str(ys)
mac_key = bytes(mac_key, encoding="ASCII")
h.update(mac_key)

print("hashed_certificate_calculated:",h.hexdigest())

if(hashed_cert.to_bytes(32,'big').hex() != h.hexdigest()) :
    print("Certificate non validate!")
    #s.close()
    #exit(-1)

#compute MAC(secretKey||MAC_S)
mac_value = array_data[6]
print("mac_value:", mac_value)
print("secret_key:",secret_key[-16:].hex().encode())


m = SHA256.new()
m.update(bytes.fromhex(secret_key[-16:].hex()+mac_value))


print("hash:",m.hexdigest())

#send finished message to the server
msg = "FINISHED {}\r\n".format(m.hexdigest())
s.sendall(bytes(msg,encoding="utf-8"))



#received data from server

'''
key = secret_key[-16:]
print(key.hex())
iv= bytes([0x0]) * 16 # iv=0
cipher= AES.new(key,AES.MODE_CBC,iv)
length = 16 - (len(ciphertext) % 16)
ciphertext += bytes([length])*length

'''


key = secret_key[-16:]

iv= bytes([0x0]) * 16 # iv=0
cipher= AES.new(key,AES.MODE_CBC,iv)
cipher2= AES.new(key,AES.MODE_CBC,iv)
message = "Test message"
cleartext = message.encode()
length = 16 - (len(cleartext) % 16)
cleartext += bytes([length])*length
ciphertext = cipher.encrypt(cleartext)
print("cipertext:", ciphertext.hex())
print(ciphertext)
#send finished message to the server
msg = "DATA {}\r\n".format( ciphertext.hex())
s.sendall(bytes(msg,encoding="utf-8"))
print(msg)

data = s.recv(1024)
array_data = data.decode("UTF-8").split()
error_checking(data,array_data)


print(array_data[1])
cleartext = cipher2.decrypt(ciphertext= bytearray.fromhex(array_data[1]))
cleartext = unpad(cleartext)
message = cleartext.decode()
print("msg:", message)

