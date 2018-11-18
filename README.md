Account_Model

Required Primitives:

public,private = Generate_keys()

signature = sign(message, private_key, 'SHA-256')

verification = verify_sig(message,signature,public_key)

m = serialize(message)
m = unserialize(message)
