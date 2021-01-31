from PyKCS11 import *
import platform
import sys
from os import listdir 
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from OpenSSL.crypto import load_certificate, load_crl, FILETYPE_ASN1, FILETYPE_PEM, Error, X509Store, X509StoreContext, X509StoreFlags, X509StoreContextError
from cryptography.x509.oid import NameOID    
from cryptography.hazmat.primitives.serialization import Encoding
from cryptography.hazmat.primitives.asymmetric import padding, padding
from cryptography.exceptions import *
from OpenSSL.crypto import *
from getpass import getpass
import base64
import unicodedata
import traceback 

class PinError(Exception):
	pass

class C_Card:

    def __init__(self):
        self.pkcs11 = PyKCS11.PyKCS11Lib()
        #self.lib = "libpteidpkcs11.so"  #Linux
        self.lib = "pteidpkcs11.dll"     #Windows
        self.pkcs11.load(self.lib)
        self.certificate = None
        self.st = self.loadCertificate()
        self.session = self.initialization()
        self.infoCC = self.infoCC()
    	

    #Load de todos os certificados para usar o CC
    def loadCertificate(self):
        cert_root = ()
        cert_trust = ()
        crl = ()
        st = X509Store()
        dir = ['crl/','certs/']

        #percorrer crl   rb =  read byte
        for c in listdir(dir[0]):
            try:
                info = open(dir[0]+"/"+c, 'rb').read()
            except IOError: print("Error: reading {:s}{:s}".format(dir[0], c))

            else:
                if ".crl" in c:
                    tmp = load_crl(FILETYPE_ASN1, info)
                    st.add_crl(tmp)
                
            crl = crl + (tmp,)

        print("Loaded certificate(CRL)!")

        for c in listdir(dir[1]):
            try:
                info = open(dir[1]+"/"+c,'rb').read()
                
            except  IOError: 
                print("Error: reading {:s}{:s}".format(dir[1], c))
                exit(10)
            
            else:
                if ".cer" in c:
                    try:
                        if "0012" in c or "0013" in c or "0015" in c:
                            auth = load_certificate(FILETYPE_PEM,info)
                            st.add_cert(auth)
                        elif "Raiz" in c:
                            raiz =  load_certificate(FILETYPE_ASN1,info)
                            st.add_cert(raiz)
                        else:
                            auth = load_certificate(FILETYPE_ASN1,info)
                            st.add_cert(auth)
        
                    except:
                        print("Error Loading!")
                        exit(10)
                    else:
                        cert_trust = cert_trust + (auth,)
                
                elif ".crt" in c:
                    try:
                        if "ca_ecce_001" in c or "-self" in c:
                            raiz = load_certificate(FILETYPE_PEM,info)
                            st.add_cert(raiz)
                        else:
                            raiz = load_certificate(FILETYPE_ASN1,info)
                            st.add_cert(raiz)
        
                    except:
                        print("Error Loading!")
                        exit(10)
                else:
                    cert_root = cert_root + (raiz,)

        print("All certificates loaded with sucess(Root and Auth)!")

        return st

    #get certificates  -  sessionId - identifica o jogar com cartão

    def getCerts(self,sessionId):
    
        info = self.session[sessionId].findObjects(template = ([(PyKCS11.CKA_CLASS, PyKCS11.CKO_CERTIFICATE), (PyKCS11.CKA_LABEL,"CITIZEN AUTHENTICATION CERTIFICATE")]))

        try:
            file_der = bytes([i.to_dict()['CKA_VALUE']for i in info ][0])
        except:
            print("Certifcate not found!")
            return None #?? nao tem certificado mas pode continuar

        else:
            try:
                cert = x509.load_der_x509_certificate(file_der,default_backend()).public_bytes(Encoding.PEM)

            except :
                print("Error loading")
                return None

            else: 
                print("Loaded certificate from CC!")
                cert = x509.load_pem_x509_certificate(cert,default_backend())

                return cert
    
    ## info of the CC
    def infoCC (self, cert = None):
        if not cert:
            cert =  self.getCerts(0)

        print("#")
        name = cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME)[0].value
        print( name)
        serial_number = cert.subject.get_attributes_for_oid(NameOID.SERIAL_NUMBER)[0].value
        serial_number = int(serial_number[2:10])

        return name, serial_number

    #inicilização
    def initialization(self):
        
        try:
            pkcs11 = PyKCS11Lib()
            pkcs11.load(self.lib)
        except PyKCS11Error:
            print("Can't load the PyCKS11 lib")

        else:
            try:
                print("Starting configuration: ")
                self.slots = pkcs11.getSlotList(tokenPresent = True)
                print("Found "+ str(len(self.slots))+" slots!")

                if len(self.slots) < 1:
                    exit(-1)
                slot_list = []
                for i in range(0,len(self.slots)):
                    slot_list.append(pkcs11.openSession(self.slots[i]))
                return slot_list
            except:
                traceback.print_exc(file=sys.stdout)
                print("No card found!")
                exit(11)

    #verificar os certificados

    def cert_verf(self,certs_trust):
        stCont = None
        stCont = X509StoreContext(self.st, certs_trust).verify_certificate()

        if stCont is None:
            print("Smartcard verified!")
            return True
        else:
            return False

    
    #assinar com CC
    def sign(self,sessionId,msg):
        try:
            data = bytes(msg,'utf-8')

        except:
            data = msg

        session = self.pkcs11.openSession(sessionId)
        key_priv = session.findObjects([(PyKCS11.CKA_CLASS, PyKCS11.CKO_PRIVATE_KEY), (PyKCS11.CKA_LABEL, 'CITIZEN AUTHENTICATION KEY')])[0]
        sign = bytes(session.sign(key_priv,data,Mechanism(CKM_SHA256_RSA_PKCS, None)))
        session.closeSession()

        return sign

    #verify signture ( vai buscar a chave publica ao cartao)
    def sign_verf( self, certs,data, sign):
        key_pub =  certs.public_key()
        
        if isinstance(key_pub, rsa.RSAPublicKey):
            print("Has public key!")
        else:
            print("Doesn't have public key")

        try:
            data =  bytes(data,'utf-8')
        except:
            data = data

        try:
            key_pub.verify(sign,data, padding.PKCS1v15(),hashes.SHA256())
            print("Success!")
            return True
        except:
            print("Failed!")
            return False

    def getPublicKey(self):
        certs = self.getCerts(0)
        key_pub = certs.public_key()

        if isinstance(key_pub, rsa.RSAPublicKey):
            print("Has public key!")
            return key_pub

        return 0

    #Login - entrar com o cartão prints 2x and i dont know why
    def login (self, slot):
        session = self.session[0]

        pin = None
        pin =  input("Pin : ")
        try:
            session.login(pin)
        except PyKCS11Error:
            raise PinError()


    def logout ( self,sessionIdx):
        session =  self.session[slot]
        session.logout()
        session.closeSession()

    