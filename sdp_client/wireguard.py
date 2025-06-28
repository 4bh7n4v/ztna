from  wireguard_tools import *

private_key = WireguardKey.generate()
public_key = private_key.public_key()
print(type(public_key))

def get_public_key():
    return public_key
