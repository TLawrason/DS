import dsh

mhost = "127.0.0.1"
mport = 5000
bhost = "127.0.0.2"
bport = 5000
print('Customer...')
if len(dsh.sys.argv) > 1:
    mhost = dsh.sys.argv[1]
    mport = int(dsh.sys.argv[2])
    bhost = dsh.sys.argv[3]
    bport = int(dsh.sys.argv[4])
con1 = dsh.socket.socket(dsh.socket.AF_INET, dsh.socket.SOCK_STREAM);
con1.connect((mhost,mport))
mpu_key = dsh.RSA.import_key(dsh.receive(con1), passphrase=None)
con2 = dsh.socket.socket(dsh.socket.AF_INET, dsh.socket.SOCK_STREAM);
con2.connect((bhost,bport))
bpu_key = dsh.RSA.importKey(dsh.receive(con2), passphrase=None)
cpr_key,cpu_key = dsh.key_pair_generation()
wrong_pr,wrong_pu = dsh.key_pair_generation()
export_key = cpu_key.export_key(format='PEM', passphrase=None, pkcs=1)
dsh.send(con1,export_key.decode())
dsh.send(con2,export_key.decode())
I1 = b'Order for 1 $30 router'
I2 = b'12345678901234'
md = dsh.MD(I1,I2,mpu_key,bpu_key,wrong_pu,wrong_pr)
dsh.send(con1,md)
R,ver = dsh.receipt_verifier(dsh.receive(con1),mpu_key,cpr_key)
R = R.decode('utf-8')
print(R)
if ver: 
    if 'not verified' not in R:
        dsh.send(con2,md)
        R_O = dsh.receive(con1)
        R,ver = dsh.receipt_verifier(R_O,mpu_key,cpr_key)
        R = R.decode('utf-8')
        print(R)
    else:
        con2.close()
        con1.close()
        exit(1)
else:
    exit(1)