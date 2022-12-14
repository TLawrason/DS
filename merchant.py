import dsh

host = '127.0.0.1'
port = 5000
port2 = 5001
if len(dsh.sys.argv) > 1:
    host = dsh.sys.argv[1]
    port = int(dsh.sys.argv[2])
    port2 = int(dsh.sys.argv[3])
pr_key,pu_key = dsh.key_pair_generation()
export_key = pu_key.export_key(format='PEM', passphrase=None, pkcs=1)
merchant = dsh.socket.socket(dsh.socket.AF_INET, dsh.socket.SOCK_STREAM)
merchant.bind((host,port))
merchant.listen()
print('Merchant Server...')
while True:
    c, addr = merchant.accept()
    print('New customer connected with merchant...')
    dsh.send(c,export_key.decode())
    cpu_key = dsh.RSA.import_key(dsh.receive(c),passphrase=None)
    ds,sb,sc = dsh.receive(c)
    ds = ds.encode('latin-1')
    sb = sb.encode()
    sc = sc.encode()
    md = dsh.hash(sb,sc)
    if dsh.PKCS1_v1_5.new(cpu_key).verify(md,ds):
        print('Valid Customer Signature...')
        I1 = dsh.decryptor(sb,pr_key)
        print('Customer Order Information: {}'.format(I1.decode('utf-8')))
        R = b'Order Verified! Verify Payment Information Now...'
        dsh.send(c,dsh.receipt(R,pr_key,cpu_key))
        b_m_socket = dsh.socket.socket(dsh.socket.AF_INET, dsh.socket.SOCK_STREAM)
        b_m_socket.bind((host,port2))
        b_m_socket.listen()
        b_m,addr = b_m_socket.accept()
        bpu_key = dsh.RSA.import_key(dsh.receive(b_m), passphrase=None)
        dsh.send(b_m,export_key.decode())
        R,ver = dsh.receipt_verifier(dsh.receive(b_m),bpu_key,pr_key)
        R = R.decode('utf-8')
        print(R)
        if ver:
            if 'not verified' not in R:
                R = b'Payment Information Confirmed and Verified, Order Complete!'
                dsh.send(c,dsh.receipt(R,pr_key,cpu_key))
            else: 
                R = b'Payment information was not confirmed or verified, order canceled...'
                dsh.send(c,dsh.receipt(R,pr_key,cpu_key))
        else: 
            R = b'Payment Information was not confirmed or verified, the order has been canceled.'
            dsh.send(c,dsh.receipt(R,pr_key,cpu_key))
            c.close()
    else: 
        print('Customer order and signature not verified, order could not be made. Relaying info to the customer...')
        R = b'Customer order and signature not verified, order could not be made.'
        dsh.send(c,dsh.receipt(R,pr_key,cpu_key))
        c.close()