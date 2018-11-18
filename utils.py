import rsa
from rsa.pkcs1 import sign, verify
import pickle

#mainly wrappers for readibility

def gen_key(bits=512):
    #wraps RSA function
    public, private = rsa.newkeys(bits)
    return public, private

def verify_sig(message,signature,pub_key):
    #wraps the RSA function
    try:
        result =  verify(message,signature,pub_key)
        if result=='SHA-256':
            result=True
    except:
        result=False
    return result

def serialize(m):
    #wraps pickle
    return pickle.dumps(m)

def unserialize(m):
    #wrapper
    return pickle.loads(m)
