import rsa.pem
import rsa

def get_n_and_e_of_key(key):
    result = rsa.PublicKey.load_pkcs1(key)
    return result.n, result.e