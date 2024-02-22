# SCITT Demo for Election Data Security


## Introduction

SCITT -- Supply Chain Integrity, Transparancy and Trust may be used for election data security.
    This demonstration provides a proof of concept (POC) for securing ballot image data so it can be
    successfully audited with a minimum of risk that the images may have been altered.
    
### Status: 
This demonstration is not fully working correctly, but provides all the steps required.
    Creation of the public key manifest is working but creating the image_signed_hash_manifest and checking it
    is not fully working. This demo creates two hacked images where one is changes and the hash digest is not
    changed to match, and one where both the image and hash manifest are modified. 
    
## Voting System Scanner Deployment
    
In our hypothetical election jurisdiction, there are 500,000 voters and 500 precincts where each precinct has one ballot scanner.
    We assume further that the scanners are new and we will be going through an initialization process of these scanners in the
    secure air-gapped warehouse of the election office. We assume here that each voting system scanner can internally generate a private key
    which is known to no one, and is infeasible to extract from the device. This is commonly available today in integrated 
    circuits called a hardware security module. They tend to use a noise source to generate a random number with sufficient entropy
    which is the basis for the public/private key pair.
    
The Election Manangement System (EMS) runs in an air-gapped network. The EMS also has means to generate a private/public key pair.
    For purposes of simulation, we will generate a random key pair that is not anchored further to any trust anchor, such as a
    certificate authority (CA) and likely using X.509.
    
In these first few sections, we will define a few convenience functions for:
* Converting to/from base64 encoding
* Generate random public/private key pair.
* Generate a random nonce of specified length
* Create a hash digest of a block of data 
* Verify a that a signature, a signed value, and a public key are consistent.

```python
    # import base64
    # import cbor2  # CBOR library
    # from cryptography.exceptions import InvalidSignature
    # from cryptography.hazmat.primitives import hashes, serialization
    # from cryptography.hazmat.primitives.asymmetric import padding
    # from cryptography.hazmat.primitives.asymmetric import rsa
    # from cryptography.hazmat.backends import default_backend
    
    def to_base64(data):
        return base64.b64encode(data).decode('utf-8')
        
    def from_base64(base64_data):
        return base64.b64decode(base64_data.encode('utf-8'))

    def generate_random_key_pair_base64():
        # Generate a random RSA key pair
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )

        # Serialize the public key to CBOR format
        public_key_cbor = cbor2.dumps(private_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

        # Encode the public key as Base64
        public_key_cbor_base64 = to_base64(public_key_cbor)

        # Return the private key and the Base64 encoded public key
        return private_key, public_key_cbor_base64
    
    
    def private_key_to_base64(private_key):
        # Serialize the private key to PEM format
        private_key_pem = private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
        
        # PEM format is already base64 encoded.
        private_key_base64 = private_key_pem.decode('utf-8')
        
        return private_key_base64
    
    
    def generate_nonce(length=32):
        """
        Generate a random nonce.
            length (int): Length of the nonce in bytes. Default is 32 bytes (256 bits).
        Returns:
            bytes: Random nonce.
        """
        return os.urandom(length)
```



## Define a function to generate hash digests

To secure this file, we need to create a hash digest of the csv file.
        Therefore, we need a function to generate say a sha256 hash digest of
        the file. The algorithm and number of bits can be changed needed.

```python
    def generate_sha256_hash(input_string):
        # Encode the input string as bytes (UTF-8 encoding is commonly used)
        if isinstance(input_string, str):
            input_bytes = input_string.encode('utf-8')
        else:
            input_bytes = input_string

        # Create a new SHA-256 hash object
        sha256_hash = hashlib.sha256()

        # Update the hash object with the input bytes
        sha256_hash.update(input_bytes)

        # Get the hexadecimal representation of the hash digest
        hash_digest = sha256_hash.hexdigest()

        return hash_digest
```



## Code to create and check digital signatures.

We also need to be able to cryptographicaly "sign" data using the private key,
        and to check those signatures. The 'sign_data' function accepts some data
        and signs it with the private key, creating a digital signature in base64 format.
        
The verify signature function accepts a signature in base64 encoding and
        verifies it.
        
We also need to be able to generate a random number which will be used only once.
        This is traditionally called a nonce.

```python
    def sign_data_to_base64(data, private_key) -> str:
        if isinstance(data, str):
            data = data.encode('utf-8')
    
        signature = private_key.sign(
            data,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        # Encode the signature as Base64 for communication
        signature_base64 = to_base64(signature)
        return signature_base64

    def sign_data_using_base64_private_key(data: bytes, private_key_base64: str) -> str:

        # Decode base64 string to bytes
        private_key_bytes = base64.b64decode(private_key_base64)

        # Load the private key
        private_key = serialization.load_pem_private_key(
            private_key_bytes,
            password=None,
            backend=default_backend()
        )

        signature = private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        signature_base64 = base64.b64encode(signature).decode('utf-8')
        return signature_base64
```



## Verify Signature

We assume that the public_key_request can be appropriately and securely
        transmitted to the scanner device using thumbdrives. The Scanner checks the
        proof that the EMS has the associated private key based on the request.
        For that we need to have a function for checking a signature.

```python
    def verify_signature(signature_base64: str, data: bytes, public_key_cbor_base64: str) -> bool:
        try:
            # Decode the Base64 encoded signature and public key
            signature = base64.b64decode(signature_base64)
            public_key_cbor = base64.b64decode(public_key_cbor_base64)

            # Load the public key from CBOR format
            public_key = serialization.load_pem_public_key(
                cbor2.loads(public_key_cbor),
                backend=default_backend()
                )

            # Verify the signature
            public_key.verify(
                signature,
                data,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except (InvalidSignature, ValueError, Exception):
            return False
```



## Generate EMS private and public keys as Base64.

It is essential to acquire the public key from each scanner. 
        Unfortunately RATS, the Remote Attestation protocol for IOT devices does not
        provide such a request. Therefore, we will design our own.
        
First, we need to have a EMS Public and Private key.

```python
    client_private_key, client_public_key_cbor_base64 = generate_random_key_pair_base64()
    
    client_private_key_base64 = private_key_to_base64(client_private_key)

    md_report += pr(f"{client_private_key_base64 = }\n\n{client_public_key_cbor_base64 = }\n\n")
```


client_private_key_base64 = '-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEAneXIAijOQA7zReIHwLKqwiFUm/pWbPrdVIwmeYhCgNM02tyy\nDJU00BxG9k3eb6HtsDePCzqE2Fw6mVLT32T3ab6z7D8SR2NQLvgp7kvTY4jqu7mq\nrjoxN9uzvC3M94CzLvmvbDVfrjfDeC5DThSkMOW2n1ig46TqvXHkzCaxcXnRAuCl\nCynP9bNG0t2tkWsS8t4NA+DvtzwflCZkdbzNrmJdWr3xQMu47LktRKxy1/2OkKGL\nROSkyyRMxUtBGZTAGjuvbDFB+lpzrDJeHrbppF7VCKeD24xYRjTpOo/IRvhDhdPX\nxx6N8K2Jfs+rwxjhoiXsBfrELPig7LefuUsGpQIDAQABAoIBAAFWd0uXY2n1Bnge\n2mB2Uw6KgEBDDnTlajcjadcJQcD8KRw6lvKW2Af0WWCQV9Rby5r82YQnloULwP5Y\nDo37ucHmWPllLmc27vC67wYDE/Mpr41wHQNVYGHgBWWQgMZPC5WYDXWt/RXJiKkt\nwSm58Isugw3WDyTmmouI2b6mDEZRFb1bp9BBo/rW8A5DLvIvsrq9fCyzYoQlosIL\nO/8dNPT14hoKdld9rCFAmIB758bWuPpzJ60PUj9EyOQsXre3lTchQ9Uul/M6sUUn\nqjwiGG6PIHdPV+KLA1hzJ11rCHv2YkJy+nnTluF1t83eNQKO03iQ+7UQ/fIE3R/O\nAY5cAKECgYEAyMkEL8fDkhPnQUrKayiuP27YxGQMsJgPC4AVrGA9hg5t1RXW12OG\n4Ju2MrhxTArXWsPBAI7CmgpkCmijHj0H7HdS8GzdHBG1VjvAiJq7qZUomB6afLOU\nDFZ0/4cvepPk+u1lZa7bEWmxJEi2g88/lV5bwlo7Nt9YXG4NLXeMywUCgYEAyVGJ\n2bLD14mLD7KcyaxUqr2rL99P0v1y+Msba4DxtCAzqv+ZlTe+gedTi74u0D3DC35v\nwZfR6FzrED3gUdlMp/f7jRzev8B3s5Ug2sujY7hGtYJJVgx4D1M46NxXeSfl4fkH\nFsflGv3kagNDDYzhAdqwyz9PDKoKPmxk5DL2XyECgYAF1VE50iPsaoedbf7TfisR\nzLaffgigWMqXGvGGQIWJD4JBXpEPUOTqQZvZfWJNQ0Neb7F7wqoEr6iYZNHYXw2L\n4SuXsJH77sfF6ZZ+YYByPNMhGEKEvPLgKOLdSaAnf4R3hc4cVignKVrsIvCqg6rl\nPAiObPCrd3GpvcjEOWTtwQKBgGvE3YGPg+0+8RVvLSV8vjpEnH5dEfNFwCVVPRF4\njms5jc8tUv8hPzd1KTE2lwLc/SuK/LJq3nCARUmFhi7qn3GPe7bXzJpjovCclWDr\nAEVioV+LJk0NEbxKdb2aLq1p4VLtp5DXY1rmrT7fDicT0mPWuSukcWG7KQ6vofbT\nHTZhAoGAboRI7qjobpMSqiEr6+UUeRggwK0EkKluGf4+XdL9Gi6dc92jEEwxjRYR\n55nyje03coC7hNLJGlbJkxPGaXXt4Ijmx4Lgw3cvMvM+PoDoqWfzElZZpnBX0jO4\nKL0+qPGGvc9Bd84H1zruhodreSHNTIhURJR4HgZ8zK4NntBCYYc=\n-----END RSA PRIVATE KEY-----\n'

client_public_key_cbor_base64 = 'WQHDLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFuZVhJQWlqT1FBN3pSZUlId0xLcQp3aUZVbS9wV2JQcmRWSXdtZVloQ2dOTTAydHl5REpVMDBCeEc5azNlYjZIdHNEZVBDenFFMkZ3Nm1WTFQzMlQzCmFiNno3RDhTUjJOUUx2Z3A3a3ZUWTRqcXU3bXFyam94Tjl1enZDM005NEN6THZtdmJEVmZyamZEZUM1RFRoU2sKTU9XMm4xaWc0NlRxdlhIa3pDYXhjWG5SQXVDbEN5blA5Yk5HMHQydGtXc1M4dDROQStEdnR6d2ZsQ1prZGJ6TgpybUpkV3IzeFFNdTQ3TGt0Ukt4eTEvMk9rS0dMUk9Ta3l5Uk14VXRCR1pUQUdqdXZiREZCK2xwenJESmVIcmJwCnBGN1ZDS2VEMjR4WVJqVHBPby9JUnZoRGhkUFh4eDZOOEsySmZzK3J3eGpob2lYc0JmckVMUGlnN0xlZnVVc0cKcFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='


## Create a request for the scanner's public key

The request for the scanner's public key can be provided to the device using a
        secure communication protocol with USB thumbdrives. The protocol will not be
        described here, but the data transferred using USB thumbdrives will be further
        encrypted so it will not be possible to view or alter the data on the thumbdrive if it is
        intercepted. For purposes of this proof of concept, we can assume this is a 
        reliable channel.
        
The request of the scanner's public key will include the public key of the 
        EMS and a nonce, which is further signed by the EMS, to provide proof that the
        public key is associated with the EMS's private key.

```python
    nonce = generate_nonce()
    signed_nonce_base64 = sign_data_to_base64(nonce, client_private_key)
    
    public_key_request = {
        'client_public_key_cbor_base64': client_public_key_cbor_base64,
        'nonce_base64'            : to_base64(nonce),
        'signed_nonce_base64'     : signed_nonce_base64
        }
        
    # the request:
    md_report += pr(f"public_key_request:\n\n{pprint.pformat(public_key_request)}\n\n")
```


public_key_request:

{'client_public_key_cbor_base64': 'WQHDLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFuZVhJQWlqT1FBN3pSZUlId0xLcQp3aUZVbS9wV2JQcmRWSXdtZVloQ2dOTTAydHl5REpVMDBCeEc5azNlYjZIdHNEZVBDenFFMkZ3Nm1WTFQzMlQzCmFiNno3RDhTUjJOUUx2Z3A3a3ZUWTRqcXU3bXFyam94Tjl1enZDM005NEN6THZtdmJEVmZyamZEZUM1RFRoU2sKTU9XMm4xaWc0NlRxdlhIa3pDYXhjWG5SQXVDbEN5blA5Yk5HMHQydGtXc1M4dDROQStEdnR6d2ZsQ1prZGJ6TgpybUpkV3IzeFFNdTQ3TGt0Ukt4eTEvMk9rS0dMUk9Ta3l5Uk14VXRCR1pUQUdqdXZiREZCK2xwenJESmVIcmJwCnBGN1ZDS2VEMjR4WVJqVHBPby9JUnZoRGhkUFh4eDZOOEsySmZzK3J3eGpob2lYc0JmckVMUGlnN0xlZnVVc0cKcFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==',
 'nonce_base64': '+PjEpFV0T08R80xD0RbiBWHk6AJPFzq9C1MXhJWfc3E=',
 'signed_nonce_base64': 'VAkeGS7WidoX0hKuhSG0egB4vXtN1Z9nZr+MZO16lHGlUK6irw1yPwbZxcYvRzgQEliK/S4vVBAlGTPZGwyCxkeM/MTf9ZAjApOl01zLxNqeoQ7J75MNgR2q9IBQ9ugpEoZJ5ec13LAIrBKJ/0ZnbDWv0DSsTnIeYqZALYX7zQFkwKCbfVmxP5dfLcaL5vR/Duc/fFvoKoHJvKzZ4H9K/xk7Ahg+Cxfgl5U1HiSQ+B2C06l9RrkBI1MzFlAHnsZhBdAyrYYvszL9uyS8sCqJU9T1wawAEs2hklQcTa4t+qKAIuSVIb4q+WeSgjn/yI+s3s/p3VTK0x0BX1HwLzak/g=='}


## Scanner checks request

With that function available, we can now check that the request is well-formed.

```python
    # verify that the request is well-formed.
    if not verify_signature(
            signature_base64        = public_key_request['signed_nonce_base64'], 
            data                    = from_base64(public_key_request['nonce_base64']), 
            public_key_cbor_base64  = public_key_request['client_public_key_cbor_base64']):
            
        validation_str = "Error: public_key is NOT consistent with the signed nonce."    
    else:
        validation_str = "Success: public_key is consistent with the signed nonce."    
    
    md_report += pr(validation_str) + "\n\n"
```


Success: public_key is consistent with the signed nonce.


## Scanner creates a response.

The scanner acts as a server and creates a response by creating a key pair, 
        and signs the nonce and returns the signature of the nonce.

```python
    server_private_key, server_public_key_cbor_base64 = generate_random_key_pair_base64()
    
    nonce_base64 = public_key_request['nonce_base64']
    nonce = from_base64(nonce_base64)
    
    signed_nonce_base64 =  sign_data_to_base64(nonce, server_private_key)

    scanner_response = {
        'server_id'                     : 10001,
        'status'                        : validation_str,
        'server_public_key_cbor_base64' : server_public_key_cbor_base64,
        'nonce_base64'                  : nonce_base64,
        'signed_nonce_base64'           : signed_nonce_base64
        }

    md_report += pr(f"scanner_response:\n\n```{pprint.pformat(scanner_response)}```\n\n")
```


scanner_response:

```{'nonce_base64': '+PjEpFV0T08R80xD0RbiBWHk6AJPFzq9C1MXhJWfc3E=',
 'server_id': 10001,
 'server_public_key_cbor_base64': 'WQHDLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUFuTDlTYXN4Qm9Fc21rVVY0bTdsQgpWWXkwelBJWUJvZSt3eW52cGhEYmZDbEF6eTZxeUVyNThMQ1lkTlFDS01SWTJwalEvUE5oK1Q4Ni9UeTVpcTQ2CklITnorK3k3RmFaWStTK3dCV2NUb1c2emkxOHZqZ2ZlWG5pY1VLQkFSTWk0MkNubUw5bXdDMGxrci9JMmZqRDgKM2NWN1JYYUJoaUxRZHhLTkJIVUw4RmFEWDV3NkoyTHZyS2hvOGpiVGVwZkZZK016d2llY2t6S0tyNzhxdzNmOQpsUUpmYWpLZ3owWURPWVpKbko4bytyRWNmYTdvVDRpT0N1K0hWWHZVZVRUd29pNVQ5blV3djBnUzc3VWJvNmcvCkN2V1c2Q0ZCWmJ3dmlBVEt0WU5xSHJ0MVBCZG5OemlXeHVPMzRRV1VWQ0FYb25sZ0R3KzdLMGljT211ZmVDM2kKNXdJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==',
 'signed_nonce_base64': 'Y2KXP5RGfXIh+Yhnsbbi49RYfFO+q7hcaNbkg6Hho15/wFFjJBn7i65WWjhzHeysQMnw28dZWR9eHHQR7l6wcz7IXzAvoIKCGdKEDDK5NBxL7bgidcgs3Fe9QYSeuFXrkClCsFlIGO2/niarBDb1MPqhYJXYEGgXNKpPc8zRa5PLcW4C+9SoFSfc/src02CbcASwOYvypg0pv0c+2eOpZKrgpjWjBjyrcKEKLBarRWHhyZvEGsLoGBScsXt7HJJ4809Z5p57CSwECrl+1Lm1P82qkqM0lE2Ai0VxRaWeMb4QZHQ0SEJj6CGJ7rl0Du+fw4wTArjf8G9tcfLz7fzRHQ==',
 'status': 'Success: public_key is consistent with the signed nonce.'}```


## Client checks the response.

The EMS checks the response to validate the server_public_key.

```python
    # verify that the response is well-formed.
    if not verify_signature(
            signature_base64        = scanner_response['signed_nonce_base64'], 
            data                    = from_base64(scanner_response['nonce_base64']), 
            public_key_cbor_base64  = scanner_response['server_public_key_cbor_base64']):
            
        validation_str = "Error: public_key is NOT consistent with the signed nonce."    
    else:
        validation_str = "Success: public_key is consistent with the signed nonce."    
     
    md_report += pr(validation_str) + "\n\n"
```


Success: public_key is consistent with the signed nonce.


## Process is repeated for all 500 scanners.

We can simulate that this process is repeated for all scanners.
        The client builds a `public_key_manifest` for all scanners, and
        we can track what is inside each scanner as the `server_internal_info`
        Here, for expediency, we will simulate only 20 scanners.

```python
    public_key_manifest_daf         = daf.Pydf()
    public_key_manifest_disp_daf    = daf.Pydf()
    server_internal_info_daf        = daf.Pydf()
    server_internal_info_disp_daf   = daf.Pydf()
    
    # The follow prefix and suffix are common among all public keys:
    public_key_prefix = 'WQHDLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRU'
    public_key_suffix = 'JREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='
    
    private_key_prefix = '-----BEGIN RSA PRIVATE KEY-----\n'
    private_key_suffix = '\n-----END RSA PRIVATE KEY-----\n'
    
    number_of_precincts = 20
    lowest_precinct_num = 10001
    
    private_key_scanner_10001 = None

    for server_id in range(lowest_precinct_num, lowest_precinct_num + number_of_precincts):
    
        this_private_key, this_public_key_cbor_base64 = generate_random_key_pair_base64()
        if server_id == 10001:
            private_key_scanner_10001 = this_private_key
        nonce = generate_nonce()
        nonce_base64 = to_base64(nonce)
        private_key_base64 = private_key_to_base64(this_private_key)
        
        public_key_manifest_daf.append({
            'server_id':                        str(server_id),
            'server_public_key_cbor_base64':    this_public_key_cbor_base64,
            'nonce_base64':                     nonce_base64,
            'signed_nonce_base64':              sign_data_to_base64(nonce, this_private_key)
            })
       
        public_key_manifest_disp_daf.append({
            'server_id':                        str(server_id),
            'server_public_key_cbor_base64':    this_public_key_cbor_base64.removeprefix(public_key_prefix
                                                    ).removesuffix(public_key_suffix),
            'nonce_base64':                     nonce_base64,
            'signed_nonce_base64':              sign_data_to_base64(nonce, this_private_key)
            })
       
        server_internal_info_daf.append({
            'server_id': str(server_id),
            'server_public_key_cbor_base64':  this_public_key_cbor_base64,
            'server_private_key_base64':      private_key_base64,
            })
    
        server_internal_info_disp_daf.append({
            'server_id': str(server_id),
            'server_public_key_cbor_base64':  this_public_key_cbor_base64.removeprefix(public_key_prefix
                                                ).removesuffix(public_key_suffix),
            'server_private_key_base64':      private_key_base64.removeprefix(private_key_prefix
                                                ).removesuffix(private_key_suffix),
            })


    md_report += pr("public_key_manifest_disp_daf:\n" + 
        public_key_manifest_disp_daf.to_md(just='^<<<', max_text_len=30, max_rows=20, include_summary=True) + "\n\n")
    md_report += pr("server_internal_info_disp_daf:\n" +
        server_internal_info_disp_daf.to_md(just='^<<', max_text_len=30, max_rows=20, include_summary=True) + "\n\n")
```


public_key_manifest_disp_daf:
| server_id | server_public_key_cbor_base64  |          nonce_base64          |      signed_nonce_base64       |
| :-------: | :----------------------------- | :----------------------------- | :----------------------------- |
|   10001   | F0MzJCdEZLQXMv..zZpWEtUNWYKYnd | 0st6r/AFJuamto..ZfRE0H1yUFFCs= | rQQ++gV7j12inN..fLIh/aSzRSAA== |
|   10002   | FxaGM0anNlSHFy..GNUa1RhcDUKZlF | dE2q1vGL35ng4t..dC30hvzhhDVgA= | WsUqXpWsTv2Z/n..s+EAxfPH4GOg== |
|   10003   | E0dkZKelp3NmRX..HliSkxTUWMKZXd | C4zJ/2mTFUxthY..EiB1YUTjhjIGw= | 1w31M1LiHDpo3B..TuFBLTCSUprQ== |
|   10004   | FpN0tNWHlmd3Vo..jR0VVRLRHQKY3d | obWilndylsEEYr..ZEuTMLn0+ZUM4= | d0uQpK5xhGqeTx..ss8ODhXWhB9g== |
|   10005   | FvVUgrRXZhN1py..itSRkdGSy8KOFF | eSEK+aIXBd5omL..3sYhpfkuPgWCw= | i5SJfsYrySH8L4..BdkMFcty4/5A== |
|   10006   | F1Z0c1YlVDTk9P..2drK25Pa2EKdnd | YVEsDmDGw5QAHy..NRtcqndbJ6ySE= | gPS7tUFZbZWsur..xTu4luTe5huA== |
|   10007   | FwQjd2QzlxdW1F..jJqU3FnUncKbXd | vkzCkdYYnjLNbr..SqKNqmT/mgfOw= | TDZK+XkhDzhs3v..lSQVqMl60oog== |
|   10008   | F6VjF0dlBBaUZI..Wl5UEo2eWcKcHd | uA4Ku9bXZyPK7R..2rqq0zQSb6SSg= | B/daxPIULHdTla..aDxMGDJ511mA== |
|   10009   | F4bStlN0NVTUgz..nd1TUpJZ0kKSHd | rymQXy1IH02BA3..4qHipEE6RFJjA= | f0A0P/kB0qeanv..AMqCTheAqhyg== |
|   10010   | F0dmlLdXo0YlZI..TFDQzN2d3MKY3d | rrO3r/jDypTSnc..Qs2RZDET8BMAM= | QpYteED5Vtcctu..IWvAaKfAbyJg== |
|   10011   | F5SDlIcjdCNVgy..28zeTBURGEKZ1F | JpyzesSEJJ8JW2..mLhpZ4kEJLxgg= | vXyKNz49mPHXxo..8jx1PaUCqyfQ== |
|   10012   | FyM01JMjZUVUtR..HZEZ29NOFIKNnd | +bxEoBrw8zZRb2..Skzg8PvReIYeg= | d3pElLzRYEP09L..Oj2HdDBHLOHA== |
|   10013   | Ewc0EyalVxSStM..GlySG5kOEwKeXd | qI25vT5oVSBJFW..W+t0R0fEuJVsQ= | o2+NWBel/HUv6o..LiyXvItrbj6A== |
|   10014   | F5d3VaY3R0eTNF..0x5MW9sTlUKRFF | YcRxb4bzeUQA/Q..gbxQsrWZw4Eoo= | eEnIHKLISRptjE..1NVfGX4JN+3g== |
|   10015   | F3a0tHWUxTOHd2..lIxWmxwdmoKWXd | FEMz447HyaIgkd..lj4jLguHss6IU= | C/p+rGTow7Okd0..uhNzaIvTcshA== |
|   10016   | ExdXA0dTB2QWY5..k92TStoVEEKaXd | BuSxiwhEgbBpw2..w+d50bgeUKEQI= | AzTm3k5AAQcLec..hjPuQRFgiyxQ== |
|   10017   | F6TnhYNnp0NHdv..0RpbmhHR0UKeVF | Fp8uUiDQia1Wzu..Byz5mJXYlfut8= | Ing8dQWsqnDggU..082oxxgZT7tg== |
|   10018   | FzS0tad1JUVklV..UR3N1NwZEUKd1F | cMXUrCDTDJ3rYq..EwNkNXNgEpgJQ= | WrUgVQ3HS1jsHX..kSheplzEBLeQ== |
|   10019   | F2QjZwS01JTmli..E5VVmRiZ08Kc1F | gu0pmDenXEYXbt..jU44jjr+t6lb4= | TEE16wcyd+ckcG..PqEI76mPQzjg== |
|   10020   | FzM0pzNHZjNVg4..XE2T1dpNzgKTHd | Tb9kx8BLitSyvF..sapnYbTqI/Ux0= | mK3d8e+M8WNQkF..ZEoH/lcpM+2A== |

\[20 rows x 4 cols; keyfield=; 0 keys ] (Pydf)


server_internal_info_disp_daf:
| server_id | server_public_key_cbor_base64  |   server_private_key_base64    |
| :-------: | :----------------------------- | :----------------------------- |
|   10001   | F0MzJCdEZLQXMv..zZpWEtUNWYKYnd | MIIEpAIBAAKCAQ..PdVr1Dp0iniA== |
|   10002   | FxaGM0anNlSHFy..GNUa1RhcDUKZlF | MIIEowIBAAKCAQ..KlShKMoel88f2g |
|   10003   | E0dkZKelp3NmRX..HliSkxTUWMKZXd | MIIEpAIBAAKCAQ..23ZLzrb6GajA== |
|   10004   | FpN0tNWHlmd3Vo..jR0VVRLRHQKY3d | MIIEogIBAAKCAQ..hcolF/L8kXYGQ= |
|   10005   | FvVUgrRXZhN1py..itSRkdGSy8KOFF | MIIEogIBAAKCAQ..TcPe2x2JKe5UM= |
|   10006   | F1Z0c1YlVDTk9P..2drK25Pa2EKdnd | MIIEogIBAAKCAQ..jwxEDcNstwJ7E= |
|   10007   | FwQjd2QzlxdW1F..jJqU3FnUncKbXd | MIIEogIBAAKCAQ..mIXQUrFVXqxG8= |
|   10008   | F6VjF0dlBBaUZI..Wl5UEo2eWcKcHd | MIIEpAIBAAKCAQ..EnTOaXTLU2Ow== |
|   10009   | F4bStlN0NVTUgz..nd1TUpJZ0kKSHd | MIIEpAIBAAKCAQ..TbodZXpbEb6g== |
|   10010   | F0dmlLdXo0YlZI..TFDQzN2d3MKY3d | MIIEpAIBAAKCAQ..0Bn+4F3rG8PA== |
|   10011   | F5SDlIcjdCNVgy..28zeTBURGEKZ1F | MIIEowIBAAKCAQ../mnC7HFt/5hK+I |
|   10012   | FyM01JMjZUVUtR..HZEZ29NOFIKNnd | MIIEowIBAAKCAQ..2OZm0uXNoRdEaz |
|   10013   | Ewc0EyalVxSStM..GlySG5kOEwKeXd | MIIEowIBAAKCAQ..WtP7YWXP7AM1Uo |
|   10014   | F5d3VaY3R0eTNF..0x5MW9sTlUKRFF | MIIEpAIBAAKCAQ..ODOsUfaeXEnQ== |
|   10015   | F3a0tHWUxTOHd2..lIxWmxwdmoKWXd | MIIEpAIBAAKCAQ..zXTJHkSC5/QQ== |
|   10016   | ExdXA0dTB2QWY5..k92TStoVEEKaXd | MIIEpAIBAAKCAQ..SBGqyxLROoEw== |
|   10017   | F6TnhYNnp0NHdv..0RpbmhHR0UKeVF | MIIEpAIBAAKCAQ..HamfntyuK2TQ== |
|   10018   | FzS0tad1JUVklV..UR3N1NwZEUKd1F | MIIEowIBAAKCAQ..ebYuJCu5EtDink |
|   10019   | F2QjZwS01JTmli..E5VVmRiZ08Kc1F | MIIEowIBAAKCAQ..9qIwBLWnXv27L8 |
|   10020   | FzM0pzNHZjNVg4..XE2T1dpNzgKTHd | MIIEowIBAAKCAQ..APIa7baRT5cXUE |

\[20 rows x 3 cols; keyfield=; 0 keys ] (Pydf)



## Save public_key_manifest.csv.

Now save these two files. The first file, 'public_key_manifest.csv' will be saved to a csv file,
        and we will further commit this file to a transparancy service so it cannot be altered after the fact.
        When converting to a csv buffer, we use CRLF as line endings regardless of the platform for consistency.

```python
    public_key_manifest_buff = public_key_manifest_daf.to_csv_buff()
    # we need the buffer so we can create the hash value momentarily.
    try:
        daf.Pydf.buff_to_file(public_key_manifest_buff, "public_key_manifest.csv")
    except Exception as err:
        print(err)
        import pdb; pdb.set_trace() #temp
        pass
        
    server_internal_info_daf.to_csv_file("server_internal_info.csv")
```



## Generate a hash digest of public_key_manifest

Use the function to generate the hash value.

```python
    public_key_manifest_sha256_hash_digest = generate_sha256_hash(public_key_manifest_buff)
    
    md_report += pr(f"{public_key_manifest_sha256_hash_digest =}")
```


public_key_manifest_sha256_hash_digest ='dd29a025f2804d4f3ac3d67cbf997bc0ad84da7f5f62ef3c718a3442a30ca816'
## Set up an append-only log using merkle tree

Now, given the hash, we need to submit that to a SCITT transparancy service.
        to simulate the service, we will set up a merkle-tree using pymerkle package.
        
According to SCITT architecture document: 

The Append-only Log is empty when the Transparency Service 
is initialized. The first entry that is added to the Append-only Log MUST be a Signed Statement 
including key material. The second set of entries are Signed Statements for additional domain-specific 
Registration Policy. The third set of entries are Signed Statements for Artifacts. From here on a 
Transparency Service can check Signed Statements on registration via policy (that is at minimum, 
key material and typically a Registration Policy) and is therefore in a reliable state to register 
Signed Statements about Artifacts or a new Registration Policy.

```python
    # pip install pymerkle
    from pymerkle import InmemoryTree as MerkleTree
    from pymerkle import verify_inclusion, verify_consistency
    
    scitt_log = MerkleTree(algorithm='sha256')
    
    # we will generate a key pair to simulate real key data for the initial entry.
    # note, this is probably not an official entry but the rest of the steps won't work
    # unless this initial entry exists.
    scitt_private_key, scitt_public_key_cbor_base64 = generate_random_key_pair_base64()
    scitt_public_key_cbor = from_base64(scitt_public_key_cbor_base64)
    scitt_log.append_entry(scitt_public_key_cbor)
```



## Submit the public_key_manifest to the Merkle Tree log.

Now that the Merkle Tree is initialized, we can add the first entry, the
        public_key_manifest_sha256_hash_digest.
        
The creation of a Merkle Tree here is to allow review of SCITT architecture standards 
but in actual practice, the public_key_manifest would be sumitted to an established SCITT
transparency service.

```python
    # Get the size of the Merkle tree before appending
    previous_size       = scitt_log.get_size()
    md_report += pr(f"- {previous_size =}\n")
    
    # Add a first entry to the Merkle tree and get its index
    scitt_log_index     = scitt_log.append_entry(public_key_manifest_sha256_hash_digest.encode('utf-8'))
    md_report += pr(f"- {scitt_log_index =}\n")
    
    # Get the size of the Merkle tree after appending
    current_size        = scitt_log.get_size()
    md_report += pr(f"- {current_size =}\n")

    scitt_log_base      = scitt_log.get_leaf(scitt_log_index)
    # scitt_log_size      = scitt_log.size()
    scitt_log_root      = scitt_log.get_state() # get root-hash
    md_report += pr(f"- {scitt_log_root =}\n")
    
    inclusion_proof     = scitt_log.prove_inclusion(scitt_log_index, current_size)
    md_report += pr(f"- {inclusion_proof =}\n")
    
    # verify the inclusion
    is_included         = verify_inclusion(scitt_log_base, scitt_log_root, inclusion_proof)
    md_report += pr(f"- {is_included =}\n")

    # Prove consistency between two tree states
    consistency_proof   = scitt_log.prove_consistency(previous_size, current_size)
    md_report += pr(f"- {consistency_proof =}\n")

    # Verify the consistency proof
    state1 = scitt_log.get_state(previous_size)
    md_report += pr(f"- {state1 =}\n")
    
    state2 = scitt_log.get_state(current_size)
    md_report += pr(f"- {state2 =}\n")
    
    is_consistent = verify_consistency(state1, state2, consistency_proof)        
    md_report += pr(f"- {is_consistent =}\n")
```


- previous_size =1
- scitt_log_index =2
- current_size =2
- scitt_log_root =b'\xd8\x88=`\t\xe9\xf5\xeb%n\x99-\xb5T\xf84O\xd49\xd7\x81\xd1\xe2L\xd0\x1e\x9e\xbe\x12*\xb0{'
- inclusion_proof =<pymerkle.proof.MerkleProof object at 0x0000014B62FCF5E0>
- is_included =None
- consistency_proof =<pymerkle.proof.MerkleProof object at 0x0000014B62FCF460>
- state1 =b'\xe6\x8b\xb2\x9a\xac/G\x8aXV\x97\x88^~q\xdd\xb4\xa7\xe7\xb9M\x9e8 buBD(O\x11k'
- state2 =b'\xd8\x88=`\t\xe9\xf5\xeb%n\x99-\xb5T\xf84O\xd49\xd7\x81\xd1\xe2L\xd0\x1e\x9e\xbe\x12*\xb0{'
- is_consistent =None

## Next we will simulate getting ballot signed hash manifest.

This simulation of the data returned from the ballot scanners is a bit different from
    what would actually be the case, but is functionally equivalent. There are these differences.
    
1. Each ballot image is in a separate TIF file, for example, named with the ballot_id.
2. The images are shuffled and are NOT kept in order from when they are scanned, to make it infeasible
to connect the ballot to any individual voter, for privacy concerns.
3. The image hash digest and signature are kept in a separate file which has a similar name to the
ballot so they can be linked.
4. The images are uploaded to the EMS along with the signed hash files, and are produced to a single ZIP file.
5. Later, the image hash digests and signatures can be then gathered up and the data table shown as a result.

In this step, we will simply simulate submitting hashing and submitting the image archive zip files to the SCITT 
server.

```python
    # the following simulates the idea that we have all the images, the hashes, and signatures in the image arhives.
    image_signed_hash_manifest_csv = image_signed_hash_manifest_daf.to_csv_buff()
    
    image_archive_hash_digest   = generate_sha256_hash(image_signed_hash_manifest_csv)
    
    scitt_log_index             = scitt_log.append_entry(image_archive_hash_digest.encode('utf-8'))

    # more is needed here to demonstrate how we can check this with the scitt instance.
```


* server_info_dict['server_id'] = '10001'
* server_info_dict['server_public_key_cbor_base64'] = 'WQHDLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF0MzJCdEZLQXMvTTlrcU1KL2F4Uwp0aEM3eldzOStXc1RXODRBcU8wVFdZSEt4aTliNGtNL2lwM2dTYmwxTGV1Wnc4ZGtXcE1Eb3FLU3lxWm9rMFN6CmFjS0ZsOVNjYW1xRS9KTUpqam5NR0NiaEkrZ3lhdnQvWkRmSS9NdlFNRFBiM3pHbWE0VlRSSzZ1ZjdJQlFMTk0KNko1b01xN3g5Qm1qbWpnM3FzU1kraTlIc3BsU0pWbVBqMU96QXg4dHVxeXdHeU5ZU3dvcUZNbW1UbExFdSt1MQpLaElLbEJGMU5wWTVha0x5b0dyeXpIQzVQdHBJNnR3OTl5aCtZUDBJWE5KL1RJcTA5Y2xDbi92QlUrdkNldVhYCmtFZGNCSDAvNEV3alhYeDJ4b210c0ppWGFMMFNrYkFMaHMwYnl5VVVWaXczV04zVk1wWEtvWUtIVzZpWEtUNWYKYndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='
* server_info_dict['server_private_key_base64'] = '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAt32BtFKAs/M9kqMJ/axSthC7zWs9+WsTW84AqO0TWYHKxi9b\n4kM/ip3gSbl1LeuZw8dkWpMDoqKSyqZok0SzacKFl9ScamqE/JMJjjnMGCbhI+gy\navt/ZDfI/MvQMDPb3zGma4VTRK6uf7IBQLNM6J5oMq7x9Bmjmjg3qsSY+i9HsplS\nJVmPj1OzAx8tuqywGyNYSwoqFMmmTlLEu+u1KhIKlBF1NpY5akLyoGryzHC5PtpI\n6tw99yh+YP0IXNJ/TIq09clCn/vBU+vCeuXXkEdcBH0/4EwjXXx2xomtsJiXaL0S\nkbALhs0byyUUViw3WN3VMpXKoYKHW6iXKT5fbwIDAQABAoIBAAbhDLDO+wZEE0Xh\nGOnKwRsUS4YrBBrKueISOhIbOUN8yzZc5iv4a3Rt8M+yxULgd1ZQrmF664L4Z1pz\nnK4QwE0xvsJvdSHENpIljREo947cPkqTVPiPzznZoY5gscBs4Uxf1yZmzDVh+ybM\nbKGZV0PNVIi56FZHc8u/Wc7sKfQPK3cpUzo8/Z5py0XniGMf49t5YHDmfUR1qijP\nmWAUzDwfvDwRhZ8lj/ZqW4oHUDbeHJx4YUT7+sfMkp8tZF82IoxObY3/fKOX7cKf\nV/y5uwSaAiyyd3G2C3TkN617qLFnShe4pGvvUXQgZcWEisV/Ii2b0K53xQG3wfSL\n5l6ZLnkCgYEA1U/6ebjS3tU289KUQBlF3br20CWX7iQIU8Hx1Rw1D4jwFvzfVQ8t\nEGCAaCSUB5LwFRENEMIRJ6tzMthsqAMQpyHI/qDeMI7G3IUUIzJbz8OZfCPNH0JS\nogJ9ToeCBKy47Mhwzo4mWZ1gMMbNQ/C5E+M9TC67ISCYai0CU4kd0m0CgYEA3DW8\nSo9Ntk+wa3NZnXAxr4meNtj5+p4IoSnxOQIoLvZ4FL6AZ/oRa05+TMMEokVzW+nD\n3oQk0i1Z+porxhVauCJR0wtasrka6cBz83afGp+qWvWQVYc1tfqnKOcOhL/xOSjr\n34MzR3w/ZY5CvLMv3ULIM8GlKYFAa0tr7OLAr8sCgYBhagHgHqimPMa4uJ0dXK1M\nYjqeudxVU709yt9OzG/q5UWHqfmv1Ztl1Dwv0yyK/O6JIF1QHuBItoKIYM/WNngf\na01oAz0U/c8RG/EjVbcZ/aCVUaA2O0qTVAG3oCifS+WztKHXopEe8cDg5ZkOAtvy\nmh7/MIQiz8jrDBz42zB0TQKBgQDHn2bLaFEYXfEd1vl8AULpUCW+rr8d87j68Fye\nQ1hOClwc4fzhRQ4ZapSP3ZIL0E2dGrLWuo/uf/I7fRsFfEI6/dGTMY3MyoSdNjtm\njzf4GJmDz2xCPEnyaAC00ZCVwrJYEMKSYgtQWE/YLjhNe1p+h5WZZYflsifFnB+A\nJKZsNQKBgQCyRsEYinURm+879Fdv7OaaNNs/R4PZzdWGZffhH1FRVxQhQxxjc8o6\nX7tgEBEwsZ3Ubb9e3RO1YVnqre3FIeqxET0s0XbvD4p3mzmuc+X3uWtuCvilcVcS\nWbNqmzb4hD9ZYLekNMueVKv+zHG6k78HkLXHFkwCNIPdVr1Dp0iniA==\n-----END RSA PRIVATE KEY-----\n'
* private_key_scanner_10001 = <cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey object at 0x0000014B62F77490>
* bool(server_info_dict['server_private_key_base64'] == private_key_scanner_10001) = False
image_signed_hash_manifest_daf

| scanner_id | ballot_id |                          image_data_hex                          |                        image_hash_digest                         |                                 signature_base64                                 |
| ---------: | --------: | ---------------------------------------------------------------: | ---------------------------------------------------------------: | -------------------------------------------------------------------------------: |
|      10001 |     50001 | 60e15dbe45a6c1547df0230796bcd21cd015ca884c53a2be49f27285cda562ae | ef2e94d7572ec788dee0d3a05ea9f401c373cd1fe3af15786ccfe68afaa9d0c8 | hfPQapPRafjw0loOsfH+I9RBHjIJuxGYfY7kpU0..I1A5oBEnHInOPGfHkUibYImuvIfJxS9N+p5ug== |
|      10001 |     50002 | a50c2fe5b1c5215986423d4570912faa958c35fa4c69b59c3af8adbac5b410db | 903b2954b3f7087058fe186946ec34584c1ffece116b555a4d2efe25e3779b41 | Q8jPqNwYxGVKtETpzQ5CUgUObZxgHbDb5HpDfRa..sAlxrtvPxWaLP3CSuVUflwoUQKqfHf12qR2kg== |
|      10001 |     50003 | 872698d944a656a128c16b7e700d7a1bbc58530cd8c29cda648a4b297792cbc1 | 7c589544cac01aef372827f3358e2403a82bf2185801bba4095b716d387201b5 | Gdyv0C1FIK7XN6IGnjCrNcW2cnWNAqVDljIMu6K../5TRhI1G2xd0hM5i94gt+0/Afh5ExivS5fBeQ== |
|      10001 |     50004 | 6b3adf7e960ad543a5e2e5bde0ef57fed0daf68734642b2ad8f195abd90fa420 | 3b7e63a4de154c99998a10a2b223477d7cbb1abfcecd4c8241e2959c4cf3d286 | IH8qgkrWv9/TEZFXdUxMaHFcDGV69p+xIidG93v..ZHb/S7TUgvI/3PE7eVHZuL0CyFEUUCA7kBGLg== |
|      10001 |     50005 | 6fc4814ced225f2a54c35b8415e99f7e3a2e019d09d64ec8d9e1d2b7f0207c8a | 57691957abcf4913aabd730d5e020ee40c35381b2766b86e8482ef3fb8328085 | OsddVxqmFcRv3K+xtsFPG6vJmg9K0XskfAoTHs7..SeuYa5EZm7JRVFgpXkkeKFLBcRs35o1a1jb8w== |
|        ... |       ... |                                                              ... |                                                              ... |                                                                              ... |
|      10001 |     50016 | a4d5bbb6b1399ce73a1441e07277a932e1e1f23f37199cfd85952678cda2fe14 | 342c250baa43b7ff683bc67bc5ca9477b934df98675c96d81d8b556415e1feea | T4IZBaVcl/7Mdpa6EuROXD+Q/Ex9+lz6cwVO8At..Kb1Ph84TIwoNsEgUTIj3YHJTnsZl4FCSHo3aA== |
|      10001 |     50017 | 5d4f82e5ba133b877a54f497fb7ac65c91fc4b1f1475604503b0a1f40b6952d0 | 639f8b72540b96d0012504bc5aae2bb6dd0934808a77cdaa38946397b2674f90 | EpUdquRWzPUMww/azGeC8JC7odBGJMA001q6Hwe..QB2qzC44XhlaDstPweBmbeY0kS8R2GJmBZE1A== |
|      10001 |     50018 | 8df7886f02008f9c4297589e4a809114b78e2d5700e619394715e4cb02d86869 | 81b4bc9ebf983256e7e890f089908536fb3bf50ad4564a0f83dbe74f741dc8ce | W2N4HteLuFQU5PMfYMU5tpfVY0ETNSzXMl1Vhyk..HkmuxBolyBMBq86wqO57ESDvg86XSfmrlIfew== |
|      10001 |     50019 | c1538bc027d1ff127b8939405607903b749dafbb1cf01f0d7aab868bc9baf83d | a532efcac890ab675b049406d2f82dae0ef9d3991089ba52719d1cb4f2bc72be | po3kCf8ffJ/quVJNHujq+2fThwORls+ncoK8kCU..Fd5w7mCDstMR1ECoq9QAhPX6W1lHYFvVYTzMg== |
|      10001 |     50020 | 7a5592774408f33ae303466db8871173f588914124ae5ea507131b1e3b3f94ad | 64ef9490130ad221e4b74fd6451230cf79cf4fd2fb00151eff5aec4770fe801c | tKP0iS6AZ7fJCAa3FfwtjFciGm0RaXhAzYbxTKk..ANN+D1oQLAcL8tuikNSmlb93d0wmxYMw72Rog== |

\[20 rows x 5 cols; keyfield=; 0 keys ] (Pydf)



## Next we will simulate getting ballot signed hash manifest.

This simulation of the data returned from the ballot scanners is a bit different from
    what would actually be the case, but is functionally equivalent. There are these differences.
    
1. Each ballot image is in a separate TIF file, for example, named with the ballot_id.
2. The images are shuffled and are NOT kept in order from when they are scanned, to make it infeasible
to connect the ballot to any individual voter, for privacy concerns.
3. The image hash digest and signature are kept in a separate file which has a similar name to the
ballot so they can be linked.
4. The images are uploaded to the EMS along with the signed hash files, and are produced to a single ZIP file.
5. Later, the image hash digests and signatures can be then gathered up and the data table shown as a result.

In this step, we will simply simulate submitting hashing and submitting the image archive zip files to the SCITT 
server.

```python
    # the following simulates the idea that we have all the images, the hashes, and signatures in the image arhives.
    image_signed_hash_manifest_csv = image_signed_hash_manifest_daf.to_csv_buff()
    
    image_archive_hash_digest   = generate_sha256_hash(image_signed_hash_manifest_csv)
    
    scitt_log_index             = scitt_log.append_entry(image_archive_hash_digest.encode('utf-8'))

    # more is needed here to demonstrate how we can check this with the scitt instance.
```



## Recover signed hash manifest as a table.

It is very important that we can check that ballot images have not been altered since 
        they were first scanned. We will simulate that here by assuming that we have
        obtained the ballot images as a ZIP archive, and we have gathered up the 
        hash digest and signature for each image from the file.
        
The result of that operation will be to obtain the following:

```python
    md_report += pr(f"image_signed_hash_manifest_daf\n\n{image_signed_hash_manifest_daf}\n\n")
```


image_signed_hash_manifest_daf

| scanner_id | ballot_id |                          image_data_hex                          |                        image_hash_digest                         |                                 signature_base64                                 |
| ---------: | --------: | ---------------------------------------------------------------: | ---------------------------------------------------------------: | -------------------------------------------------------------------------------: |
|      10001 |     50001 | 60e15dbe45a6c1547df0230796bcd21cd015ca884c53a2be49f27285cda562ae | ef2e94d7572ec788dee0d3a05ea9f401c373cd1fe3af15786ccfe68afaa9d0c8 | hfPQapPRafjw0loOsfH+I9RBHjIJuxGYfY7kpU0..I1A5oBEnHInOPGfHkUibYImuvIfJxS9N+p5ug== |
|      10001 |     50002 | a50c2fe5b1c5215986423d4570912faa958c35fa4c69b59c3af8adbac5b410db | 903b2954b3f7087058fe186946ec34584c1ffece116b555a4d2efe25e3779b41 | Q8jPqNwYxGVKtETpzQ5CUgUObZxgHbDb5HpDfRa..sAlxrtvPxWaLP3CSuVUflwoUQKqfHf12qR2kg== |
|      10001 |     50003 | 872698d944a656a128c16b7e700d7a1bbc58530cd8c29cda648a4b297792cbc1 | 7c589544cac01aef372827f3358e2403a82bf2185801bba4095b716d387201b5 | Gdyv0C1FIK7XN6IGnjCrNcW2cnWNAqVDljIMu6K../5TRhI1G2xd0hM5i94gt+0/Afh5ExivS5fBeQ== |
|      10001 |     50004 | 6b3adf7e960ad543a5e2e5bde0ef57fed0daf68734642b2ad8f195abd90fa420 | 3b7e63a4de154c99998a10a2b223477d7cbb1abfcecd4c8241e2959c4cf3d286 | IH8qgkrWv9/TEZFXdUxMaHFcDGV69p+xIidG93v..ZHb/S7TUgvI/3PE7eVHZuL0CyFEUUCA7kBGLg== |
|      10001 |     50005 | 6fc4814ced225f2a54c35b8415e99f7e3a2e019d09d64ec8d9e1d2b7f0207c8a | 57691957abcf4913aabd730d5e020ee40c35381b2766b86e8482ef3fb8328085 | OsddVxqmFcRv3K+xtsFPG6vJmg9K0XskfAoTHs7..SeuYa5EZm7JRVFgpXkkeKFLBcRs35o1a1jb8w== |
|        ... |       ... |                                                              ... |                                                              ... |                                                                              ... |
|      10001 |     50016 | a4d5bbb6b1399ce73a1441e07277a932e1e1f23f37199cfd85952678cda2fe14 | 342c250baa43b7ff683bc67bc5ca9477b934df98675c96d81d8b556415e1feea | T4IZBaVcl/7Mdpa6EuROXD+Q/Ex9+lz6cwVO8At..Kb1Ph84TIwoNsEgUTIj3YHJTnsZl4FCSHo3aA== |
|      10001 |     50017 | 5d4f82e5ba133b877a54f497fb7ac65c91fc4b1f1475604503b0a1f40b6952d0 | 639f8b72540b96d0012504bc5aae2bb6dd0934808a77cdaa38946397b2674f90 | EpUdquRWzPUMww/azGeC8JC7odBGJMA001q6Hwe..QB2qzC44XhlaDstPweBmbeY0kS8R2GJmBZE1A== |
|      10001 |     50018 | 8df7886f02008f9c4297589e4a809114b78e2d5700e619394715e4cb02d86869 | 81b4bc9ebf983256e7e890f089908536fb3bf50ad4564a0f83dbe74f741dc8ce | W2N4HteLuFQU5PMfYMU5tpfVY0ETNSzXMl1Vhyk..HkmuxBolyBMBq86wqO57ESDvg86XSfmrlIfew== |
|      10001 |     50019 | c1538bc027d1ff127b8939405607903b749dafbb1cf01f0d7aab868bc9baf83d | a532efcac890ab675b049406d2f82dae0ef9d3991089ba52719d1cb4f2bc72be | po3kCf8ffJ/quVJNHujq+2fThwORls+ncoK8kCU..Fd5w7mCDstMR1ECoq9QAhPX6W1lHYFvVYTzMg== |
|      10001 |     50020 | 7a5592774408f33ae303466db8871173f588914124ae5ea507131b1e3b3f94ad | 64ef9490130ad221e4b74fd6451230cf79cf4fd2fb00151eff5aec4770fe801c | tKP0iS6AZ7fJCAa3FfwtjFciGm0RaXhAzYbxTKk..ANN+D1oQLAcL8tuikNSmlb93d0wmxYMw72Rog== |

\[20 rows x 5 cols; keyfield=; 0 keys ] (Pydf)



## Simulate hacked ballot image files.

To test that the cryptographic protection will actually catch changed values, 
        we will simulate that the second image has been altered by a hacker after the
        security data was generated, but he changed nothing else.
        
In the case of the third image, we will simulate that the hacker also modified
        the image, and also was sophisticated and altered the hash value as well
        so it matches the altered ballot image data.
        
The hacker can't generate a new signature successfully because he does not have the 
private key generated inside the scanner in both cases.

The new table shows the changed image data but it does have a corresponding hash value
which is easily generated by the hacker to be consistent with the changed imaged data.

```python
    # create an example of a hacked image where the image data is changed alone.
    hacked_binary_image_data = generate_nonce(length=32)       # random data to simulate newly hacked image data.
    # hacked_hash_digest = generate_sha256_hash(hacked_binary_image_data)
    image_signed_hash_manifest_daf[1,'image_data_hex'] = hacked_binary_image_data.hex()

    # create an example of a hacked image where the image data is changed AND the hash value is changed.            
    hacked_binary_image_data = generate_nonce(length=32)       # random data to simulate newly hacked image data.
    hacked_hash_digest = generate_sha256_hash(hacked_binary_image_data)

    image_signed_hash_manifest_daf[2,'image_data_hex'] = hacked_binary_image_data.hex()
    image_signed_hash_manifest_daf[2,'image_hash_digest'] = hacked_hash_digest
            
    md_report += pr(f"hacked image_signed_hash_manifest_daf\n\n{image_signed_hash_manifest_daf}\n\n")
```


hacked image_signed_hash_manifest_daf

| scanner_id | ballot_id |                          image_data_hex                          |                        image_hash_digest                         |                                 signature_base64                                 |
| ---------: | --------: | ---------------------------------------------------------------: | ---------------------------------------------------------------: | -------------------------------------------------------------------------------: |
|      10001 |     50001 | 60e15dbe45a6c1547df0230796bcd21cd015ca884c53a2be49f27285cda562ae | ef2e94d7572ec788dee0d3a05ea9f401c373cd1fe3af15786ccfe68afaa9d0c8 | hfPQapPRafjw0loOsfH+I9RBHjIJuxGYfY7kpU0..I1A5oBEnHInOPGfHkUibYImuvIfJxS9N+p5ug== |
|      10001 |     50002 | 461e95459b55274d40edcdff59cd658c765bfa13a107a749b053e9f8ea7ef383 | 903b2954b3f7087058fe186946ec34584c1ffece116b555a4d2efe25e3779b41 | Q8jPqNwYxGVKtETpzQ5CUgUObZxgHbDb5HpDfRa..sAlxrtvPxWaLP3CSuVUflwoUQKqfHf12qR2kg== |
|      10001 |     50003 | 811128acec0165872bde5fbd6559eb455a377058b4359fdcae4b20516c1b0341 | 35d287a23cf57170916dacfbfc2672daf3fa5d700606ea6af451fae4e528d538 | Gdyv0C1FIK7XN6IGnjCrNcW2cnWNAqVDljIMu6K../5TRhI1G2xd0hM5i94gt+0/Afh5ExivS5fBeQ== |
|      10001 |     50004 | 6b3adf7e960ad543a5e2e5bde0ef57fed0daf68734642b2ad8f195abd90fa420 | 3b7e63a4de154c99998a10a2b223477d7cbb1abfcecd4c8241e2959c4cf3d286 | IH8qgkrWv9/TEZFXdUxMaHFcDGV69p+xIidG93v..ZHb/S7TUgvI/3PE7eVHZuL0CyFEUUCA7kBGLg== |
|      10001 |     50005 | 6fc4814ced225f2a54c35b8415e99f7e3a2e019d09d64ec8d9e1d2b7f0207c8a | 57691957abcf4913aabd730d5e020ee40c35381b2766b86e8482ef3fb8328085 | OsddVxqmFcRv3K+xtsFPG6vJmg9K0XskfAoTHs7..SeuYa5EZm7JRVFgpXkkeKFLBcRs35o1a1jb8w== |
|        ... |       ... |                                                              ... |                                                              ... |                                                                              ... |
|      10001 |     50016 | a4d5bbb6b1399ce73a1441e07277a932e1e1f23f37199cfd85952678cda2fe14 | 342c250baa43b7ff683bc67bc5ca9477b934df98675c96d81d8b556415e1feea | T4IZBaVcl/7Mdpa6EuROXD+Q/Ex9+lz6cwVO8At..Kb1Ph84TIwoNsEgUTIj3YHJTnsZl4FCSHo3aA== |
|      10001 |     50017 | 5d4f82e5ba133b877a54f497fb7ac65c91fc4b1f1475604503b0a1f40b6952d0 | 639f8b72540b96d0012504bc5aae2bb6dd0934808a77cdaa38946397b2674f90 | EpUdquRWzPUMww/azGeC8JC7odBGJMA001q6Hwe..QB2qzC44XhlaDstPweBmbeY0kS8R2GJmBZE1A== |
|      10001 |     50018 | 8df7886f02008f9c4297589e4a809114b78e2d5700e619394715e4cb02d86869 | 81b4bc9ebf983256e7e890f089908536fb3bf50ad4564a0f83dbe74f741dc8ce | W2N4HteLuFQU5PMfYMU5tpfVY0ETNSzXMl1Vhyk..HkmuxBolyBMBq86wqO57ESDvg86XSfmrlIfew== |
|      10001 |     50019 | c1538bc027d1ff127b8939405607903b749dafbb1cf01f0d7aab868bc9baf83d | a532efcac890ab675b049406d2f82dae0ef9d3991089ba52719d1cb4f2bc72be | po3kCf8ffJ/quVJNHujq+2fThwORls+ncoK8kCU..Fd5w7mCDstMR1ECoq9QAhPX6W1lHYFvVYTzMg== |
|      10001 |     50020 | 7a5592774408f33ae303466db8871173f588914124ae5ea507131b1e3b3f94ad | 64ef9490130ad221e4b74fd6451230cf79cf4fd2fb00151eff5aec4770fe801c | tKP0iS6AZ7fJCAa3FfwtjFciGm0RaXhAzYbxTKk..ANN+D1oQLAcL8tuikNSmlb93d0wmxYMw72Rog== |

\[20 rows x 5 cols; keyfield=; 0 keys ] (Pydf)



## Check Images for consistency -- Recover server public key.

to check the images for consistency, we need to be able to recover the scanner's public key
        from the public key manifest. In this simulation, we need only to have the first record from
        the public_key_manifest file, because we are workign with the data from the first scanner only.

```python
    public_key_record = public_key_manifest_daf.irow(0)
    server_public_key_cbor_base64 = public_key_record['server_public_key_cbor_base64']
    
    md_report += pr(f"* {public_key_record['server_id'] = }\n")
    md_report += pr(f"* {public_key_record['server_public_key_cbor_base64'] = }\n")
    md_report += pr(f"* {public_key_record['nonce_base64'] = }\n")
    md_report += pr(f"* {public_key_record['signed_nonce_base64'] = }\n")
```


* public_key_record['server_id'] = '10001'
* public_key_record['server_public_key_cbor_base64'] = 'WQHDLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF0MzJCdEZLQXMvTTlrcU1KL2F4Uwp0aEM3eldzOStXc1RXODRBcU8wVFdZSEt4aTliNGtNL2lwM2dTYmwxTGV1Wnc4ZGtXcE1Eb3FLU3lxWm9rMFN6CmFjS0ZsOVNjYW1xRS9KTUpqam5NR0NiaEkrZ3lhdnQvWkRmSS9NdlFNRFBiM3pHbWE0VlRSSzZ1ZjdJQlFMTk0KNko1b01xN3g5Qm1qbWpnM3FzU1kraTlIc3BsU0pWbVBqMU96QXg4dHVxeXdHeU5ZU3dvcUZNbW1UbExFdSt1MQpLaElLbEJGMU5wWTVha0x5b0dyeXpIQzVQdHBJNnR3OTl5aCtZUDBJWE5KL1RJcTA5Y2xDbi92QlUrdkNldVhYCmtFZGNCSDAvNEV3alhYeDJ4b210c0ppWGFMMFNrYkFMaHMwYnl5VVVWaXczV04zVk1wWEtvWUtIVzZpWEtUNWYKYndJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='
* public_key_record['nonce_base64'] = '0st6r/AFJuamto6mgFSlJVCs+MHxhlZfRE0H1yUFFCs='
* public_key_record['signed_nonce_base64'] = 'CVU7QMe9fDM6V5CF3Fo3E85lAj5mX+mtN+V05+//QrlkWlqilFPHguFoYZZpafmG9cUul97lVdT7eW3WtXwtQ8o1vmBK8fIYITTAzvdnkuAsEu2WK4VwwWuLaiaD2LavqyM93phpQqOxZJt7JrK80PZcabZJuxbkMJY+hOJ1zu4btfQH3hWY6gztIp+rXx2XeiqbXoYtVRJ4RnVMt6O7b8xLa6UwLVwS6kOqYF9+mFgwv/ZeX/CwWLFKRgtNkJ7YU81Tbl78Yin2GX5WIjfKBtRcPHMiqLYU5MrF2iRBsOvZXuNQHzDsSzEZA5eNTixC08ujZj5o9BX1r7WezEyQbA=='

## Check Images for consistency -- create independent hashes and signatures.

Here, we take the table of the image hash manifest and add three columns,
        
* 'calc_image_hash_digest'    -- this is the hash digest independently calculated from the image.
* 'is_hash_verified'          -- this is whether the hash calculated from the image matches that provided in the manifest.
* 'is_signature_verified'     -- verify the signature of the calculated hash using the scanner public key. 
        
This process would be repeated for each image from each scanner.

```python
    # create a new table with three new columns:
    calc_hash_manifest_daf = daf.Pydf(cols=image_signed_hash_manifest_daf.columns() + 
                                ['calc_image_hash_digest', 'is_hash_verified', 'is_signature_verified'])
    
    for image_signed_hash_manifest_da in image_signed_hash_manifest_daf:
        calc_hash_manifest_da = image_signed_hash_manifest_da       # adopt existing values.
        
        # this recovery of binary image data does not actually have to happen in non-simulation as we have the images.
        binary_image_data = bytes.fromhex(image_signed_hash_manifest_da['image_data_hex'][2:])
        
        # calculate the hash digest for the binary image data and save it in the array.
        calculated_image_hash_digest = generate_sha256_hash(binary_image_data)
        calc_hash_manifest_da['calc_image_hash_digest'] = calculated_image_hash_digest
        
        calc_hash_manifest_da['is_hash_verified'] = \
            bool(calc_hash_manifest_da['image_hash_digest'] == calculated_image_hash_digest)
        
        # using the server public key from the public_key_manifest, verify the signature
        # (speed of this can be improved by precalculating the binary server public key)
        calc_hash_manifest_da['is_signature_verified'] = \
            verify_signature(image_signed_hash_manifest_da['signature_base64'], 
                                calculated_image_hash_digest, 
                                server_public_key_cbor_base64)
    
        calc_hash_manifest_daf.append(calc_hash_manifest_da)
    
    md_report += pr(f"calc_hash_manifest\n\n{calc_hash_manifest_daf}\n\n")
```


calc_hash_manifest

| scanner_id | ballot_id |                          image_data_hex                          |                        image_hash_digest                         |                                 signature_base64                                 |                      calc_image_hash_digest                      | is_hash_verified | is_signature_verified |
| ---------: | --------: | ---------------------------------------------------------------: | ---------------------------------------------------------------: | -------------------------------------------------------------------------------: | ---------------------------------------------------------------: | ---------------: | --------------------: |
|      10001 |     50001 | 60e15dbe45a6c1547df0230796bcd21cd015ca884c53a2be49f27285cda562ae | ef2e94d7572ec788dee0d3a05ea9f401c373cd1fe3af15786ccfe68afaa9d0c8 | hfPQapPRafjw0loOsfH+I9RBHjIJuxGYfY7kpU0..I1A5oBEnHInOPGfHkUibYImuvIfJxS9N+p5ug== | e8d491b0e351c983de837455c4702fc261a2f60587e0641cd6c889cf75a3d358 |            False |                 False |
|      10001 |     50002 | 461e95459b55274d40edcdff59cd658c765bfa13a107a749b053e9f8ea7ef383 | 903b2954b3f7087058fe186946ec34584c1ffece116b555a4d2efe25e3779b41 | Q8jPqNwYxGVKtETpzQ5CUgUObZxgHbDb5HpDfRa..sAlxrtvPxWaLP3CSuVUflwoUQKqfHf12qR2kg== | 2a2623645be8145796beb0b483c8093823dc2a0603e4082522b3c381ba70895d |            False |                 False |
|      10001 |     50003 | 811128acec0165872bde5fbd6559eb455a377058b4359fdcae4b20516c1b0341 | 35d287a23cf57170916dacfbfc2672daf3fa5d700606ea6af451fae4e528d538 | Gdyv0C1FIK7XN6IGnjCrNcW2cnWNAqVDljIMu6K../5TRhI1G2xd0hM5i94gt+0/Afh5ExivS5fBeQ== | eedb18290e47c921b64b1984ab4917e5eaa1b45b093d4412fc99ee7cc9849a45 |            False |                 False |
|      10001 |     50004 | 6b3adf7e960ad543a5e2e5bde0ef57fed0daf68734642b2ad8f195abd90fa420 | 3b7e63a4de154c99998a10a2b223477d7cbb1abfcecd4c8241e2959c4cf3d286 | IH8qgkrWv9/TEZFXdUxMaHFcDGV69p+xIidG93v..ZHb/S7TUgvI/3PE7eVHZuL0CyFEUUCA7kBGLg== | e3f137ab174e7a0a9fba8fec7acd50d95f27ae67f6040b7749037808a5ed42bf |            False |                 False |
|      10001 |     50005 | 6fc4814ced225f2a54c35b8415e99f7e3a2e019d09d64ec8d9e1d2b7f0207c8a | 57691957abcf4913aabd730d5e020ee40c35381b2766b86e8482ef3fb8328085 | OsddVxqmFcRv3K+xtsFPG6vJmg9K0XskfAoTHs7..SeuYa5EZm7JRVFgpXkkeKFLBcRs35o1a1jb8w== | 4be9d5093be32b8711c30dd3e0a979e29fcdb497863f8b6872ddc9af7df84623 |            False |                 False |
|        ... |       ... |                                                              ... |                                                              ... |                                                                              ... |                                                              ... |              ... |                   ... |
|      10001 |     50016 | a4d5bbb6b1399ce73a1441e07277a932e1e1f23f37199cfd85952678cda2fe14 | 342c250baa43b7ff683bc67bc5ca9477b934df98675c96d81d8b556415e1feea | T4IZBaVcl/7Mdpa6EuROXD+Q/Ex9+lz6cwVO8At..Kb1Ph84TIwoNsEgUTIj3YHJTnsZl4FCSHo3aA== | e970c51ef8882b943ae23b22f78a8f2a861ea7134fe60b8e3173faa5aab20ae6 |            False |                 False |
|      10001 |     50017 | 5d4f82e5ba133b877a54f497fb7ac65c91fc4b1f1475604503b0a1f40b6952d0 | 639f8b72540b96d0012504bc5aae2bb6dd0934808a77cdaa38946397b2674f90 | EpUdquRWzPUMww/azGeC8JC7odBGJMA001q6Hwe..QB2qzC44XhlaDstPweBmbeY0kS8R2GJmBZE1A== | a095ef31b596f5d9f083f26bb4d730335bc6cbcca676283069eda055987f801d |            False |                 False |
|      10001 |     50018 | 8df7886f02008f9c4297589e4a809114b78e2d5700e619394715e4cb02d86869 | 81b4bc9ebf983256e7e890f089908536fb3bf50ad4564a0f83dbe74f741dc8ce | W2N4HteLuFQU5PMfYMU5tpfVY0ETNSzXMl1Vhyk..HkmuxBolyBMBq86wqO57ESDvg86XSfmrlIfew== | 5d893235213a4bcbe134070cd003c81121605f21a8f2ef775afea9ac15a7e00f |            False |                 False |
|      10001 |     50019 | c1538bc027d1ff127b8939405607903b749dafbb1cf01f0d7aab868bc9baf83d | a532efcac890ab675b049406d2f82dae0ef9d3991089ba52719d1cb4f2bc72be | po3kCf8ffJ/quVJNHujq+2fThwORls+ncoK8kCU..Fd5w7mCDstMR1ECoq9QAhPX6W1lHYFvVYTzMg== | da9209585ea077f01b5e810d9a36826ebc3dc250295101e96733e695536df316 |            False |                 False |
|      10001 |     50020 | 7a5592774408f33ae303466db8871173f588914124ae5ea507131b1e3b3f94ad | 64ef9490130ad221e4b74fd6451230cf79cf4fd2fb00151eff5aec4770fe801c | tKP0iS6AZ7fJCAa3FfwtjFciGm0RaXhAzYbxTKk..ANN+D1oQLAcL8tuikNSmlb93d0wmxYMw72Rog== | bc51e8f72829d3a5a7d991dcf8b3a5429910958075963a610679a00db99c6ee6 |            False |                 False |

\[20 rows x 8 cols; keyfield=; 0 keys ] (Pydf)


