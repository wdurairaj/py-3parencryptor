import etcd
import json
import argparse
import string
from configparser import SafeConfigParser
from Crypto.Cipher import AES
import base64
import sys
import subprocess
import os
import time

LEN16 = 16
LEN24 = 24
LEN32 = 32

BACKENDROOT = '/backend'
backendroot = BACKENDROOT + '/'
BACKEND = 'DEFAULT'

CONF_FILE_DIR = '/etc/hpedockerplugin'
CONF_FILE_NAME = 'hpe.conf'

parser = argparse.ArgumentParser(description='Encryption Tool'
                                 ,usage='hpe3parencryptor [OPTIONS]')

parser.add_argument ("-a"
                     ,nargs=2,help="key addition, need key and secret",metavar=('key','secret'))

parser.add_argument("-d"
                    ,action='store_true',help="This will delete the key stored")


parser.add_argument("--backend", dest='backend',
                    help="backend name, default is %s" % BACKEND,
                    default=BACKEND)

args = parser.parse_args()

if args.backend:
   BACKEND= args.backend

if len(sys.argv) == 1:
    parser.print_help()
    sys.exit(0)

if args.d == False:
    args.key = args.a[0]
    args.secret = args.a[1]

    if len(args.secret) == 0 :
        print("Enter valid text and try again")
        print("ABORTING")
        sys.exit(-1)

    if len(args.key) == 0:
        print("Enter valid key/passphrase")
        print("ABORTING")
        sys.exit(-1)
        

conf_file = SafeConfigParser()
conf_file.read(os.path.join(CONF_FILE_DIR, CONF_FILE_NAME))
CONF = conf_file.defaults()

backend_list = conf_file.keys()

if BACKEND not in backend_list:
    print("Backend is not present")
    sys.exit(-1)


if len(CONF) == 0:
    print("please Check the %s file on %s path" % (CONF_FILE_NAME, CONF_FILE_DIR))
    sys.exit(-1)



host_etcd_ip_address = CONF.get('host_etcd_ip_address')
host_etcd_port_number = int(CONF.get('host_etcd_port_number'))
host_etcd_client_cert = CONF.get('host_etcd_client_cert')
host_etcd_client_key = CONF.get('host_etcd_client_key')

if host_etcd_ip_address == None or host_etcd_port_number == None:
    print("Please check %s for host_etcd_ip_address or host_etcd_port_number" % CONF_FILE_NAME)
    sys.exit(-1)



def encrypt(message, passphrase):
    # passphrase MUST be 16, 24 or 32 bytes long, how can I do that ?
    aes = AES.new(passphrase, AES.MODE_CFB, '1234567812345678')
    sample =  base64.b64encode(aes.encrypt(message))
    return sample.decode("utf-8")

def decrypt(encrypted, passphrase):
    aes = AES.new(passphrase, AES.MODE_CFB, '1234567812345678')
    #return aes.decrypt(base64.b64decode(encrypted))
    return aes


def key_check(key):
    KEY_LEN = len(key)
    padding_string = string.ascii_letters

    if KEY_LEN < LEN16:
        KEY = key + padding_string[:LEN16 - KEY_LEN]
    elif KEY_LEN > LEN16 and KEY_LEN < LEN24:
        KEY = key + padding_string[:LEN24 - KEY_LEN]
    elif KEY_LEN > LEN24 and KEY_LEN < LEN32:
        KEY = key + padding_string[:LEN32 - KEY_LEN]
    elif KEY_LEN > LEN32:
        KEY = key[:LEN32]
    else:
        KEY = key

    return KEY


def check_plugin_stat():
    cmd = ["""docker ps | grep hpestorage"""]
    try:
        subprocess.check_output(cmd, shell=True)
    except:
        return False
    else:
        return True

class EtcdUtil(object):


    def __init__(self, host, port, client_cert, client_key):
        self.host = str(host)
        self.port = port
        self.client_cert = client_cert
        self.client_key = client_key

        host_tuple = ()
        if len(self.host) > 0:

            if ',' in self.host:
                host_list = [h.strip() for h in host.split(',')]

                for i in host_list:
                    temp_tuple = (i.split(':')[0], int(i.split(':')[1]))
                    host_tuple = host_tuple + (temp_tuple,)

                host_tuple = tuple(host_tuple)

        if client_cert is not None and client_key is not None:
            if len(host_tuple) > 0:
               self.client = etcd.Client(host=host_tuple, port=port,
                                          protocol='https',
                                          cert=(client_cert, client_key),
                                          allow_reconnect=True)
            else:
               self.client = etcd.Client(host=host, port=port, protocol='https',
                                      cert=(client_cert, client_key))

        else:
            if len(host_tuple) > 0:
                self.client = etcd.Client(host=host_tuple, port=port,
                                          protocol='http',
                                          allow_reconnect=True)
            else:
                self.client = etcd.Client(host, port)
        try:
            self.client.read(BACKENDROOT)
        except etcd.EtcdKeyNotFound as e:
            print('Etcd Key not present: %s' % e)
            try:
                self.client.write(BACKENDROOT, None, dir=True)
            except etcd.EtcdNotFile as e:
                print('Could be that the key has already been written by a different etcd: %s' % e)
                print('Retrying READ after a gap of 10 seconds')
                time.sleep(10)
                self.client.read(BACKENDROOT)
                print('Read successful after retry')


    def set_key(self,key, password):
        if check_plugin_stat() == False:
            try:
              self.client.read(key)
            except:
                self.client.write(key,password)
        else:
            print("Plugin is running can not perform the operation")
            print("ABORTING")
            sys.exit(-1)


    def get_key(self ,key):
        result = self.client.read(key)
        return result.value

    def delete_key(self, key):
        if check_plugin_stat() == False:
            try:
                self.client.delete(key)
                print("Key Successfully deleted")
            except etcd.EtcdKeyNotFound:
                print("Key not present")
        else:
            print("Plugin is running can not delete the key")
            print("ABORTING")
            sys.exit(-1)

cl = EtcdUtil(host_etcd_ip_address
             ,host_etcd_port_number
             ,host_etcd_client_cert
             ,host_etcd_client_key)

otpt = """ERROR: Not able to connect etcd, this could be because of:
1. etcd is not running
2. host and port in conf file is wrong."""


backendkey = backendroot + BACKEND

if args.d == True:
    try:
        passp = cl.get_key(backendkey)
        passp = key_check(passp)
        cl.delete_key(backendkey)
    except etcd.EtcdConnectionFailed:
        print(otpt)
else:
    key = key_check(args.key)
    ciph_text = encrypt(args.secret, key)
    try:
        cl.set_key(backendkey,args.key)
    except :
        print(otpt)
        sys.exit(-1)
    print("SUCCESSFUL: Encrypted password: " + ciph_text)
sys.exit(0)
