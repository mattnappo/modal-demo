import modal
import os
from dataclasses import dataclass

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

import hashlib

img = modal.Image.debian_slim(python_version="3.10").pip_install(
    "cryptography",
)

stub = modal.Stub(image=img, name='auth-server')
stub.state = modal.Dict.from_name("state-dict", create_if_missing=True)

@dataclass
class Record:
    text: str
    signature: bytes
    hash: str
    key: str

    #def __str__(self):
    #    return f'Record'

@stub.function(network_file_systems={"/vol": modal.NetworkFileSystem.from_name("auth-test")})
def new_record(text, sig, hash, key):
    record = Record(text, sig, hash, key)
    stub.state[hash] = record
    return record

@stub.function(network_file_systems={"/vol": modal.NetworkFileSystem.from_name("auth-test")})
def list_records():
    print(f"{stub.state.len()} records")
    return stub.state

@stub.function(network_file_systems={"/vol": modal.NetworkFileSystem.from_name("auth-test")})
def hash(data):
    hash_object = hashlib.sha256(data)
    return hash_object.hexdigest()

@stub.function(network_file_systems={"/vol": modal.NetworkFileSystem.from_name("auth-test")})
def listkeys():
    return set([k.split(".")[0] for k in os.listdir("/vol")])

@stub.function(network_file_systems={"/vol": modal.NetworkFileSystem.from_name("auth-test")})
def keygen(output):
    # generate & write the priv key
    private_key = ed25519.Ed25519PrivateKey.generate()
    with open(f"/vol/{output}.pem", "wb") as f:
        f.write(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    # generate & write the pub key
    public_key = private_key.public_key()
    with open(f"/vol/{output}.pub.pem", "wb") as f:
        f.write(
            public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            )
        )

@stub.function(network_file_systems={"/vol": modal.NetworkFileSystem.from_name("auth-test")})
def sign(key, message):
    # load (priv) key to sign
    with open(f'/vol/{key}.pem', "rb") as f:
        private_key = serialization.load_pem_private_key(
            f.read(),
            password=None,
        )

    data = message.encode('utf-8')
    signature = private_key.sign(data)

    # load pubkey to verify
    with open(f"/vol/{key}.pub.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
        )

    # return
    try:
        public_key.verify(signature, data)
        sig_hash = hash.remote(signature)
        record = new_record.remote(message, signature, sig_hash, key)
        return record
    except InvalidSignature:
        print("error validating signature")
        return None


@stub.function(network_file_systems={"/vol": modal.NetworkFileSystem.from_name("auth-test")})
def verify(text, sig_hash, key):
    # load pubkey to verify
    with open(f"/vol/{key}.pub.pem", "rb") as f:
        public_key = serialization.load_pem_public_key(
            f.read(),
        )

    record = stub.state[sig_hash]
    print(f"found record {record} for sig hash {sig_hash}")
    data = text.encode('utf-8')
    try:
        public_key.verify(record.signature, data)
        print("signautre is VALID")
        return True
    except InvalidSignature:
        print("signature is INVALID")
        return False

@stub.local_entrypoint()
def main(command, text='', key='', signature=''):
    if command == 'sign':
        # make key if not exists
        if key not in listkeys.remote():
            print("making new key")
            keygen.remote(key)
        else:
            print("using existing key")

        # sign
        sig = sign.remote(key, text)
        print(sig)

    elif command == 'verify':
        verify.remote(text, signature, key)
    elif command == 'list':
        print('keys', listkeys.remote())
        print('records', list_records.remote())
    else:
        print("invalid command. options are:\n\t* sign\n\t* verify\n\t* list")

