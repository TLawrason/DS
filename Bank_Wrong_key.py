import dsh


host = '127.0.0.2'
port = 5000
bhost = "127.0.0.1"
bport = 5001
if len(dsh.sys.argv) > 1:
    host = dsh.sys.argv[1]
    port = int(dsh.sys.argv[2])
    bhost = dsh.sys.argv[3]
    bport = int(dsh.sys.argv[4])
pr_key,pu_key = dsh.key_pair_generation()
export_key = pu_key.export_key(format='PEM', passphrase=None, pkcs=1)
bank = dsh.socket.socket(dsh.socket.AF_INET, dsh.socket.SOCK_STREAM)
bank.bind((host,port))
bank.listen()
print('Bank Server...')
while True:
    c, addr = bank.accept()
    print('New customer connected with bank...')
    dsh.send(c,export_key.decode())
    cpu_key = dsh.RSA.import_key(dsh.receive(c),passphrase=None)
    wrong_pr,wrong_pu = dsh.key_pair_generation()
    ds,sb,sc = dsh.receive(c)
    if ds == 0: 
        print('Connection with customer was closed ending payment transaction...')
        c.close()
        continue
    ds = ds.encode('latin-1')
    sb = sb.encode()
    sc = sc.encode()
    md = dsh.hash(sb,sc)
    b_m = dsh.socket.socket(dsh.socket.AF_INET, dsh.socket.SOCK_STREAM)
    b_m.connect((bhost,bport))
    dsh.send(b_m,export_key.decode())
    mpu_key = dsh.RSA.import_key(dsh.receive(b_m), passphrase=None)
    if dsh.PKCS1_v1_5.new(wrong_pu).verify(md,ds):
        print('Valid Customer Signature...')
        I2 = dsh.decryptor(sc,pr_key)
        print('Customer Payment Information: {}'.format(I2.decode('utf-8')))
        R = b'Payment Information Confirmed and Verified!'
        dsh.send(b_m,dsh.receipt(R,pr_key,mpu_key))
    else: 
        print('Customer payment and signature not verified, payment information was not be confirmed. Relaying info to the merchant...')
        R = b'Payment Information was not verified!'
        dsh.send(b_m,dsh.receipt(R,pr_key,mpu_key))
        c.close()