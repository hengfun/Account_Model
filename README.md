## Account Model
Implements Ethereum account model using RSA public, private key signature scheme

Required primitives:

public,private = generate_keys()\
signature = sign(message, private_key)\
verification = verify_sig(message,signature,public_key)\
m = serialize(message)\
message = unserialize(m)
