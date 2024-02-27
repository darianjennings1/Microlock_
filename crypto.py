from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet
from base64 import b64encode, b64decode

def generate_key_pair(name,password):
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size = 4096
    )
    public_key = private_key.public_key()

    write_key_file(private_key,name,'priv',password)
    write_key_file(public_key,name,'pub')

    return 0

def write_key_file(key,name,ktype,password=None):
    if ktype == 'priv':
        

        pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.BestAvailableEncryption(bytes(password, 'utf-8'))
        )

        kf = open(f'./keys/{name}_priv_key.pem','wb')
        for line in pem.splitlines():
            kf.write(line)
            kf.write('\n'.encode('utf-8'))
        kf.close()

        return 0

    elif ktype == 'pub':

        pem = key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

        kf = open(f'./keys/{name}_pub_key.pem','wb')
        for line in pem.splitlines():
            kf.write(line)
            kf.write('\n'.encode('utf-8'))
        kf.close()

        return 0

    else:
        return -1

def get_plaintext_pub_key(name):
    with open(f'./keys/{name}_pub_key.pem','r') as f:
        lines = [line for line in f]
        
        pk_string = ""

        for line in lines:
            pk_string+=line

        return pk_string

def load_pub_key_from_plaintext(ptxt_pub_key):
    return serialization.load_pem_public_key(ptxt_pub_key.encode())

def load_key(name,ktype,password=None):
    try: 
        key_path = f"./keys/{name}_{ktype}_key.pem"
        if ktype == 'priv':
            with open(key_path, "rb") as key_file:
                private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=bytes(password, 'utf-8')
            )
            return private_key

        elif ktype == 'pub':
            with open(key_path, "rb") as key_file:
                public_key = serialization.load_pem_public_key(
                key_file.read()
            )

            return public_key

        else:
            return -1
    except:
        return -1 

def lock_message(sender_key,recipient_key,data):
    sym_key = Fernet.generate_key()
    f = Fernet(sym_key)

    # encrypt the message
    enc_data = f.encrypt(data.encode('utf-8'))
    b64_enc_data = b64encode(enc_data).decode('utf-8')

    # encrypt per message symmetric key
    enc_sym_key = recipient_key.encrypt(
        sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    b64_enc_sym_key = b64encode(enc_sym_key).decode('utf-8')
    
    # sign encrypted key + encrypted message 
    message = enc_sym_key + enc_data
    signature = sender_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    b64_signature = b64encode(signature).decode('utf-8')

    payload = { 'key':  b64_enc_sym_key, 'data': b64_enc_data, 'signature': b64_signature}
    return payload

def insert_newlines(string, every=64):
    lines = []
    for i in range(0, len(string), every):
        lines.append(string[i:i+every])
    return '\n'.join(lines)

def insert_newlines2(string, every=12):
    '''returns a string where \\n is inserted between every n words'''
    words = string.split()
    ret = ''
    for i in range(0, len(words), every):
        ret += ' '.join(words[i:i+every]) + '\n'

    return ret

def encode_payload(payload):
    enc_sym_key = payload['key']
    enc_data = payload['data']
    signature = payload['signature']
    return insert_newlines("$$".join((enc_sym_key,enc_data,signature)))

def parse_full_secret_message(smess):
    parts = smess.split("$$$$$$$$$$")

    user_name = " ".join(parts[0].split(" ")[1:])
    email = parts[1].split(" ")[3]
    sender_key = parts[2]
    fsp = "".join(parts[3].split('\n'))

    return user_name, email, sender_key, fsp

def parse_secret_payload(secret_payload):
    enc_sym_key,enc_data,signature = secret_payload.split("$$")
    parsed_payload = { 'key':  enc_sym_key, 'data': enc_data, 'signature': signature}
    return parsed_payload

def unlock_message(sender_key,recipient_key,secret_payload):
    parsed_payload = parse_secret_payload(secret_payload)
    enc_sym_key = b64decode(parsed_payload['key'])
    enc_data = b64decode(parsed_payload['data'])
    signature = b64decode(parsed_payload['signature'])

    sym_key = recipient_key.decrypt(
        enc_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    f = Fernet(sym_key)
    data = f.decrypt(enc_data)
    decoded_data = data.decode('utf-8')

    try: 
        message = enc_sym_key + enc_data
        sender_key.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return insert_newlines2(decoded_data), True
    except:
        return insert_newlines2(decoded_data), False
