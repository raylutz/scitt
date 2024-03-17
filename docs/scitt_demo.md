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
    
## Outline of the process:

1. Prior to the election, the Election Management System (EMS) will configure and test individual 
voter-facing scanners, and other scanners in the central scannign facility (for mail ballots). 
As part of this process, USB thumbdrives (or other removeable media) will be used (within a secure facility) to:
    - Send the voting machine the public key of the EMS and signed nonce which will demonstrate possession of the corresponding private key.
    - Request from the voting machine its public key.
    - Voting machine scanner will respone with unique ID, public key, and will sign the nonce.
    - Voting machine may also provide other evidence of operating configuration including proof of firmware version.
    - In this initial interaction, symmetric encryption keys may be exchanged.

2. The EMS system will collect and post all the public keys of all voting machine scanners in a public key manifest. 
The hash of this manifest may be submitted to a SCITT transparency server to document who, what, when. Moving the data
from the air-gapped facility to post will use the TransGapProtocol, which essentially creates a secure channel in USB
drives.

3. During the election, the voting system scanner will
    - preferrably use a Trusted Platform Module (TPM) and Trusted Execution Environment (TEE) to maintain a trusted system configuration
    - as each ballot is scanned, the image created will be hashed and then the hash signed using the private key corresponding with the published public key.
    - The images must be shuffled to randomize the order so it is infeasible to link a voter to their ballot.
    - The signed hash will be provided in a related file, perhaps formatted as COSE block.

4. After the election, a hash manifest of all files can be created using any tool, such as QuickHash or any sha256sum type of utility. This has manifest can be submitted to a SCITT transparancy service.

5. Auditing tools can check the integrity of all files, and can also check that each image was created by the scanner and signed using the private key which corresponds to the public key previously posted.In these first few sections, we will define a few convenience functions for:
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


client_private_key_base64 = '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAwmMmt7a80mnaKLrnpKIE1og7bfWC8Yoxb9vi8OEKP0M1ITzw\nd+/H8BZ/27/F2zdsNvjhpVYOmT40DAFIcBVPsrR4lVywG6qxJOlnYCoZUPgI4gsm\n2DcNJdW6X22EV7x9tzDRFAAv6PH7/HZH8lZOkLO6Kq5IA63d1Nr4MKAJalck/z2x\nkIOY84cVsy27RHG+3CjLNgpcwg3rcc0z8C7/5t0GA8AcZZW1uRsgNgilceQlaknx\nbnILF0MIQ8KTQ/vORExGJ8kyX9baqWl9CF1ut0ap1MlnvNT16B+xuqLxSxAAchEx\n6Q2uQUGdps/fKI/Jy87Phq59eJNK1rIRqKWupQIDAQABAoIBAC4c3Mqwjh8BLthC\nLGDk8W5d/3EgkGlRrdQaDr4zOF3VCOXDYc0l4+F7yOV9mwdboK9yv36cCVcHh0vA\nwykZmSAsyT0vcXSCu8akmtoYaoyHZn4PBK4+cv9CchWgsogopg7+xN5wg+0H+I3F\nlmAx4q3XgOaOlPVQecL8letdD5a6vyx38A8baSGTPE6AcSAzBmdiOtW9IOWipV2f\nFi6cezYHrRGZrKofeGvX7/ydfF+fItzIdjgSgayPiDP6hGVOHU+A2Gau3DICF4zR\nxcykHtpz+n6QpBCv/tzbQV//Sc1lnLhClq9ts0OOMSzSQlEpoj30A9TQNpYleWnS\nvYlZ0FECgYEA3jwkloRfZoV3ablJ9bafnlKzeigEKTwnhEGrTJckyK08pjXYCkMH\nQxI9gSyXL1jyMwAleCXZ99d+eKQhD3rbC3AVQ0OZcXvVPMZIZw1A2Df/m/HHSxtn\nQ+zuaBWjd2UbVob3bSH2Mt7sKNYEbn2TP8ZxifgaL9XK2dI6ESA2/jUCgYEA3+vf\nDopYUVI9PIb2Sk3mThfJvqwsQMYyXORe+yZLufK0ATdmJ4DpQnpmfTnrwgfgoOtX\nW/XZuAP6ky4dn+WXD/0m7eNOLm+bvvpg8emb8Ino0DxP2ABNmvrhwDcimB2D1Wd+\n36ehXFlOimxqjJV/oVcUPP47yhiIndFbwqJNvLECgYEArjf18u2JIIUHDSHNwkvN\nrD9nJh+Sy4S18e/NS3i9xHhSsHZLjBfp7IGzJ73+M4cGMEcwGJWL38jXA9qfdFQ6\nvie684VeGGIc080Z23e/WwHjZ6xOMSoldVGbwIseIC5qFRYviCV0rYKnHohQ5xGY\nywlV3vRaCyAOK16sWNqpYfUCgYApE2WpjytAT6u4DLHlU4Dp1mdFuOOtRi466BGc\nVJwTkjf++SCeIoGnljhyxEtBHpzQKBuwXNsBbIlsskrw5/bcEf4wKUBQOF0DnX5n\nIglfCI1SlZ236+ZQhbEfx31rFg72+LNHZ8Kr5B4KOnUZMNtmx0iJH8HsArAc8yi3\n/XnxIQKBgHtcqGBfz+hnY5OiY+L8bSFPthszLbZ4GJQr9xq9+de8p1yRU9HKlTUL\nuE39KaBrK7GhQQe0vNhNMrANRsn0y9Y2Vat9iDr92yaxnmtXTrIvketnlwp7JjfB\nDbBY2967WaGAan//96VVTQSvpc5gTVy/U6Hb2ZJzkBYHLctV9JOg\n-----END RSA PRIVATE KEY-----\n'

client_public_key_cbor_base64 = 'WQHDLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3bU1tdDdhODBtbmFLTHJucEtJRQoxb2c3YmZXQzhZb3hiOXZpOE9FS1AwTTFJVHp3ZCsvSDhCWi8yNy9GMnpkc052amhwVllPbVQ0MERBRkljQlZQCnNyUjRsVnl3RzZxeEpPbG5ZQ29aVVBnSTRnc20yRGNOSmRXNlgyMkVWN3g5dHpEUkZBQXY2UEg3L0haSDhsWk8Ka0xPNktxNUlBNjNkMU5yNE1LQUphbGNrL3oyeGtJT1k4NGNWc3kyN1JIRyszQ2pMTmdwY3dnM3JjYzB6OEM3Lwo1dDBHQThBY1paVzF1UnNnTmdpbGNlUWxha254Ym5JTEYwTUlROEtUUS92T1JFeEdKOGt5WDliYXFXbDlDRjF1CnQwYXAxTWxudk5UMTZCK3h1cUx4U3hBQWNoRXg2UTJ1UVVHZHBzL2ZLSS9KeTg3UGhxNTllSk5LMXJJUnFLV3UKcFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='


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

{'client_public_key_cbor_base64': 'WQHDLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUF3bU1tdDdhODBtbmFLTHJucEtJRQoxb2c3YmZXQzhZb3hiOXZpOE9FS1AwTTFJVHp3ZCsvSDhCWi8yNy9GMnpkc052amhwVllPbVQ0MERBRkljQlZQCnNyUjRsVnl3RzZxeEpPbG5ZQ29aVVBnSTRnc20yRGNOSmRXNlgyMkVWN3g5dHpEUkZBQXY2UEg3L0haSDhsWk8Ka0xPNktxNUlBNjNkMU5yNE1LQUphbGNrL3oyeGtJT1k4NGNWc3kyN1JIRyszQ2pMTmdwY3dnM3JjYzB6OEM3Lwo1dDBHQThBY1paVzF1UnNnTmdpbGNlUWxha254Ym5JTEYwTUlROEtUUS92T1JFeEdKOGt5WDliYXFXbDlDRjF1CnQwYXAxTWxudk5UMTZCK3h1cUx4U3hBQWNoRXg2UTJ1UVVHZHBzL2ZLSS9KeTg3UGhxNTllSk5LMXJJUnFLV3UKcFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==',
 'nonce_base64': 'XMjPlvhRP+3pVIt2xGDjzHGl0hfVZ3UwRW1o1zH8pS8=',
 'signed_nonce_base64': 'MFZAqCIUDYAY+hPNFOV9g+8t/38cumC9Cc+/qy0gdFb4RWF5Fwp3JckC1a2h6AJCPQQQc2yRD+ZnTCB1QYbaeYkSYh/R2AcPyv5gmjnrcPlPfzjm/HX6tMPezTvxWJUDoTHVP0z1PDz6o7aR82QmHbm2pYhTnbUCnb5coqV1gx3xJpKzT65WBKKMSth5nIYjSxbDmrkGPc88HBg7VIiL3p2U1qTgytefawDw+a7X6f6KofWHeAzKQFzww4bVrxMnzqLRGQhKyVoKYQpjuDAbUVcBVm//uWx+6lZQKMAnd3jliTBi/pOHalTT8Oi1Qsx6B3XhvML8U2AqgDWQY2PvGw=='}


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

```{'nonce_base64': 'XMjPlvhRP+3pVIt2xGDjzHGl0hfVZ3UwRW1o1zH8pS8=',
 'server_id': 10001,
 'server_public_key_cbor_base64': 'WQHDLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUExMTVHQ3djNUZTQkZWN1hDSkdkSgpXSWdlUVZBS2g0N0tmK2FFd0NCdCtGN3MrZm96NlVFT0xLOUhhc0xyOThvZ1pERmZmMENQLzZYUGFZSjIxQS9KCjZVa1dNc2habWpyeU9pLzZNampheEFKaTVrNXJ5Zzl5S1FEeXY1NG0xbmF3VG03V0NadmRZVG5QNGpib09BTVkKN0lkZnk2R01QSmZVQkd0S2RtcVgvMlNKWmxzQ0JRQjJad3dWVjNYOFFjQzBrc0ZJbFQxTW4rcnNNTXNLclNWNgpuYUFEeUlHZnJLamxLUUJXNVRtTTJYTlA1bEQ1WDcvMkphTkVveUZBODZGN3pWb2ZkankyQ05oRFhhemF4MGpRCjBUK3J2eHNrTUxza1VNam1ZK1ZvKzdqcjBxZXltNERxTzNFWmE5emFXbDZvUmdXUmJFQ0wxL2d0N3lpak1TWVoKVFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg==',
 'signed_nonce_base64': 'O1durJ46sL/5VEwRIrlHODGCFUv0gA/Ini9G+NsqzSz7qGNAHHQzG/mg0FYi1UoLPevOqA0LJOMFFCERoNFFQhwMmrL6mhdRLy9Cj7qc0gGTbSXs9siWeIlW4M51gP7qgv1WYw5ZWv6qTGfG/lvDQp0+Z/0tzAuRbgwj4uM4IYzrDAWk0N/sZ834oFQg2i7lCXju++LM0nU38hNpMr3k+2VVHqYmZSnxtYEneaAo4Q5ctRPfWmvKIA3dslK1vxCqRjhvyZrJmQspRD6qBXqEDKW51OSGRCzn4yOP9jmr+CjFjQN4DmvWzeF41r28ORB7wrEgZ8caoEq4ElRo9UiJPA==',
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
    public_key_manifest_daf         = Daf()
    public_key_manifest_disp_daf    = Daf()
    server_internal_info_daf        = Daf()
    server_internal_info_disp_daf   = Daf()
    
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
|   10001   | EyeGtkcExQbFFJ..G5mSG9KM2cKWFF | 6aeH+ktvfPNfld..AJ8yBqpjs16yg= | 01Yv/aLl/TPE/X..txCBXjdXkCpQ== |
|   10002   | F1RFBhSmJudDli..VlZeWZ3QkoKS1F | drzrkBKQEz6hsT..lckuq2nBeEHzM= | mtvhUOnCgaX+9T..T7CZhzE7TX8w== |
|   10003   | F0dmloc2pDemR1..jdxQ0FTSUMKc3d | gkJsPU1OHUuKSG..AuNQ3pPuvXVYI= | laGBxR5Ie5wyFH..B2hUzPWdeOQw== |
|   10004   | F4ZjVBWVRKNk5l..Dl0Z1pES3cKS3d | k+NJJ+UZqnoeMk..O2Bmr5hNYGKEk= | A9ydolBKKe1Y3U..rtEmXKE7BM+A== |
|   10005   | ExMXNDWCtiNElx..i94SGYrN0wKL1F | WFjDzsEqHt9/cn..G/UWi00c15294= | F9RDT6buMGRE8k..NZj6TlV5HcZQ== |
|   10006   | EyU05jVEJ0WDQw..DFNOVFJS3AKTFF | zCHNFA2KZQZYJe..tiNtvAsbJhtDc= | at8G3JSv2jB83i..9JbYDJFi8Jig== |
|   10007   | FoRmZHRERKb0Vz..mFINm5WV0wKbFF | P4OnrH62x3tJT5..jxEhqcVW8LZ4I= | WmIPeAmoNwwHrz..3ibau+37ccTg== |
|   10008   | F1dzJLSmNlU2l3..WR5NFlRTDYKRnd | eAq/spCpA3M7O+..rtkldyVKa/3KA= | WyG392MxqMhHmN..akeScDkk8u+g== |
|   10009   | FsUVlRUDdIVlI1..DNXK1lJRWIKWFF | wTpZDHM+NobgtM..TXPMV/XWLiQAc= | ePSvycqJohvmN1..9VYsqPn9mLiQ== |
|   10010   | FzVlhQd3BzdmM4..HNRbzBmOU4KblF | 4fXQr5RJ5349OS..9Widf6ePM/lH0= | Nrqgz1JrgsyMGq..ycdd7N0+BwVQ== |
|   10011   | FwZWdqa2YvZFdM..zVSSGRwTlMKRnd | gsXfipXj1t3K5N..Z9/Q5XezHSyYA= | ApDujgbFUlsuRZ..rCpMEo4REH7g== |
|   10012   | FxbWVoUUZFbEtD..XNRQUc2eFMKUHd | A4L1wBNH094o0N..3jfTzIzgSnYYw= | faaKuCFwoZWnyO..TlztgkdVA3kQ== |
|   10013   | FsdHhTRk53N1pC..UpTdkR2b0gKNVF | 04csLBKVi8EULe..Z+pa2/wBky2w8= | ZS43ANbqt0ySAG..7ccwKTA1lRHA== |
|   10014   | FuU3lvYURWdy9U..UpKWmFHYXkKZXd | NMtDVMoXrecZUz..b9WzpHPPBGozg= | mwYJ7BrdszxKvB..WIxDVvJ0rjMg== |
|   10015   | ExQVc4UUYwa0dC..mUySWxUbmsKbVF | dGpgJQ2Fq8TVo4..qtJWyi0D4R2u8= | WAxhdiyBbLUqEo..UyYj5WEZuE/g== |
|   10016   | F0VGJERVBjZGM3..EwyZjQ3T1cKNXd | pHoTUK9V84ORS2..ZIuqPM8OeXShs= | Db5LTat/Bdnrh1..L3pLY3+KSFYg== |
|   10017   | FwYmFCdHdyc3Bh..UJPMDhjd00KZnd | 2HZeW54BqX0loZ..Je82cGMujtSCA= | XyxxQKMTs6vkd/..4Wo0hSqslLgw== |
|   10018   | FsU0Z0VGVNNXUv..UtTT0hERHkKYXd | 9tEGs4RGuf5b6s..bZsGE2cIx0Ig4= | B2ZRd+r5VlLXJ+..+QuG7pNVMqbA== |
|   10019   | F1RGpuSWtPbVhN..WtwNERYSHcKdXd | jv4189KnVRSiHn..hMbO8HuNlwh9w= | sy8GwsuZzr5Gaf..pIMYRheFaaJA== |
|   10020   | FxMWtPZWduZU9Q..m1LRHRjSkoKWXd | Y/HCy9K4rfrSNx..ZqvnNvITd5Jw4= | ksfJpgQpBBRV5W..9RhDIHFo8avw== |

\[20 rows x 4 cols; keyfield=; 0 keys ] (Daf)


server_internal_info_disp_daf:
| server_id | server_public_key_cbor_base64  |   server_private_key_base64    |
| :-------: | :----------------------------- | :----------------------------- |
|   10001   | EyeGtkcExQbFFJ..G5mSG9KM2cKWFF | MIIEogIBAAKCAQ..aicGMXyTmECm0= |
|   10002   | F1RFBhSmJudDli..VlZeWZ3QkoKS1F | MIIEoQIBAAKCAQ..VJVHg4WMnElg== |
|   10003   | F0dmloc2pDemR1..jdxQ0FTSUMKc3d | MIIEpAIBAAKCAQ..Dy23m8ab+E7Q== |
|   10004   | F4ZjVBWVRKNk5l..Dl0Z1pES3cKS3d | MIIEowIBAAKCAQ..4Lj3P7wyLnHj8f |
|   10005   | ExMXNDWCtiNElx..i94SGYrN0wKL1F | MIIEowIBAAKCAQ..TDUVezCvwue0QC |
|   10006   | EyU05jVEJ0WDQw..DFNOVFJS3AKTFF | MIIEogIBAAKCAQ..G9whUhPOz9o/Y= |
|   10007   | FoRmZHRERKb0Vz..mFINm5WV0wKbFF | MIIEpAIBAAKCAQ..J9G6mvcFJQuA== |
|   10008   | F1dzJLSmNlU2l3..WR5NFlRTDYKRnd | MIIEowIBAAKCAQ..75U4+Mgs/69mFl |
|   10009   | FsUVlRUDdIVlI1..DNXK1lJRWIKWFF | MIIEowIBAAKCAQ..Wpj1cwa01Rfzrn |
|   10010   | FzVlhQd3BzdmM4..HNRbzBmOU4KblF | MIIEpAIBAAKCAQ..nw16bLP2wAUA== |
|   10011   | FwZWdqa2YvZFdM..zVSSGRwTlMKRnd | MIIEoQIBAAKCAQ..6CcScx1ZVqRQ== |
|   10012   | FxbWVoUUZFbEtD..XNRQUc2eFMKUHd | MIIEowIBAAKCAQ..gKoNmom3H/BK/C |
|   10013   | FsdHhTRk53N1pC..UpTdkR2b0gKNVF | MIIEpAIBAAKCAQ..+IqdT/Hwnf6A== |
|   10014   | FuU3lvYURWdy9U..UpKWmFHYXkKZXd | MIIEowIBAAKCAQ..xZJw8qVz8lwH6K |
|   10015   | ExQVc4UUYwa0dC..mUySWxUbmsKbVF | MIIEpQIBAAKCAQ..dWkijtoItQDxQ= |
|   10016   | F0VGJERVBjZGM3..EwyZjQ3T1cKNXd | MIIEowIBAAKCAQ..Eu//jQXgOJV0cK |
|   10017   | FwYmFCdHdyc3Bh..UJPMDhjd00KZnd | MIIEogIBAAKCAQ..vpCwC0d567rcE= |
|   10018   | FsU0Z0VGVNNXUv..UtTT0hERHkKYXd | MIIEoAIBAAKCAQ..Mfl4onKIasSZoD |
|   10019   | F1RGpuSWtPbVhN..WtwNERYSHcKdXd | MIIEowIBAAKCAQ..tWIjKdN8ePtC0l |
|   10020   | FxMWtPZWduZU9Q..m1LRHRjSkoKWXd | MIIEpAIBAAKCAQ..Sot4tER8zeRQ== |

\[20 rows x 3 cols; keyfield=; 0 keys ] (Daf)



## Save public_key_manifest.csv.

Now save these two files. The first file, 'public_key_manifest.csv' will be saved to a csv file,
        and we will further commit this file to a transparancy service so it cannot be altered after the fact.
        When converting to a csv buffer, we use CRLF as line endings regardless of the platform for consistency.

```python
    public_key_manifest_buff = public_key_manifest_daf.to_csv_buff()
    # we need the buffer so we can create the hash value momentarily.
    try:
        Daf.buff_to_file(public_key_manifest_buff, "public_key_manifest.csv", fmt='.csv')
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


public_key_manifest_sha256_hash_digest ='7fbbe6f6c26c0c3ea69fe9b4ad9906b5edd026b5add06900d31894af061cc306'
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
- scitt_log_root =b"M\xca\xb7)\xd6\xe4\xcfI\x86X\xcc\xee\x94\xb8\xba\xc4w\x86\xcc\xdd\x9c.\x8c\x9eXoT\x85\xb9\xf6'\x02"
- inclusion_proof =<pymerkle.proof.MerkleProof object at 0x000002271D3D7B50>
- is_included =None
- consistency_proof =<pymerkle.proof.MerkleProof object at 0x000002271E458070>
- state1 =b'\xc0\xd1=\xe0C\xb5S\x86\x01\x93\x85\x19y5\xc0\xadR\xe6\xbf\x1a\xcd$\xfb\x07)\xeb0\xd0JH\x91\xec'
- state2 =b"M\xca\xb7)\xd6\xe4\xcfI\x86X\xcc\xee\x94\xb8\xba\xc4w\x86\xcc\xdd\x9c.\x8c\x9eXoT\x85\xb9\xf6'\x02"
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
* server_info_dict['server_public_key_cbor_base64'] = 'WQHDLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEyeGtkcExQbFFJMHUzYXRKVm9DTgp2citrZ0xBU3JabFpJckJ3OHlVZFczUEFXMjlNQ1JYeGE0ZXFUYlpzcDFCaEtuR3ZKTlQvYVNIenB5RmRzTlFtCnNESHRPTmFNU2tTQzBUVmlGdHhtSmNZTzdiUm82UEpBVUlMdTVzUzBYcXhSZmxZbHpITjFtSkhhSXdzMUhRZmcKNmIvSjVhYldzdUNZYUMrYVRScktiWUVLcDlHeURwR3ZSYWcrNXhvVlJaWno1VHhFRmlhT0JaRktyOXE1TWdNSApuc0FMR0lLVFF2TUdpR0dUS00yUXZiVFQ2alg4Znc2Y2F4NGpzMkNMVWhPdzhiRC9BMWNUK2ZTWUJQd0llVDI4Cm16VCt3RzNlbUs4Qm5aZE9BTkpkemQveTRXRG1KclcySWNBdVFEbFJZOU84Q1NoVlpTTnRwNnBkbG5mSG9KM2cKWFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='
* server_info_dict['server_private_key_base64'] = '-----BEGIN RSA PRIVATE KEY-----\nMIIEogIBAAKCAQEA2xkdpLPlQI0u3atJVoCNvr+kgLASrZlZIrBw8yUdW3PAW29M\nCRXxa4eqTbZsp1BhKnGvJNT/aSHzpyFdsNQmsDHtONaMSkSC0TViFtxmJcYO7bRo\n6PJAUILu5sS0XqxRflYlzHN1mJHaIws1HQfg6b/J5abWsuCYaC+aTRrKbYEKp9Gy\nDpGvRag+5xoVRZZz5TxEFiaOBZFKr9q5MgMHnsALGIKTQvMGiGGTKM2QvbTT6jX8\nfw6cax4js2CLUhOw8bD/A1cT+fSYBPwIeT28mzT+wG3emK8BnZdOANJdzd/y4WDm\nJrW2IcAuQDlRY9O8CShVZSNtp6pdlnfHoJ3gXQIDAQABAoIBACsUVyXJUWxN1kcz\npKnjgPtehyPeeu2zVzlg4/SK+ai/q7TOv26R5/QyqqO5GMgVH+XOkJd3Yfjz+gqE\nnv1j2W+PgYtJdDAuJGKqUm0YTOVkeg73CCG1cDvkYsDxMF3lF+j1W11F3ntvQird\ny0W4BNsxIKuNEG3/hzgFFBvRBrhc580pUqMgIFKD0BGnFF3WCaCgMjkYpiFEm+v4\npZLwmci9rS0ncf5/CnFSzKMDlOMexG0vmuSeYiWXfc70Tbmbt/ow1Px1t6wW2Q35\nie2bBZ35nnCfu+2JxZpdo+8a1FPxzO9u1x5laE+RIHQy8LiEoLBmKwrX7JKsCAs9\noRwgs2kCgYEA4IMCP0RjFYgj8Fzy4GqToj9cCB+i6mCsRO8lEXR8AjmltEGNbz+K\nnQ2zliAIG4q8P0lqHSMDaA8H2ArRG5Vj3rkEIVKBTFr7ngp+UnN9tiHEy8Mcth+r\nuBKg0lbIurgi8idjgAZKbUPoXLcKKQ5iQutAR2IlxRbQFzKPlk5pjUsCgYEA+dO7\ni9AMH4xncvIcmOzDfsBrzK9Ll15GOcB1u9p9RagGKA6w0Rdz1iRQqAJetcqFC7+r\nF1bGDceITTL87V/r04jM/JPQ49XVZIayenrI5rU2QpmLPKG+w8x1Obt3HOQb8oRv\nJMfsUtH5Wk920VRDow303CBp8U4g/E123fdMh/cCgYBuM8Bhn8bnJclGTcmmIIpR\nJLqe/jBwzX0h5SUT2VKZoQRWY6ryBYWbq8MQGK8CHepjQj0FCk+8v0wBXuXfnUfF\nZpnBZYc0HKDPpaT2AdyeDxtTTXWFbCxVEUfBl3m2NXZp2K29hNj5o1CmWe5x0q6m\n3GTT5ThW8ui3ykiy5dBn2wKBgDbhoZikOpWPpYYl08xwbr3gjY3okGWPS0QSmIqN\nA+oScE/KcmNskIDhd2qBIscy1ylukKpO4LFUPQgghFmtMcRFkCqIWmJCrl8oC/tG\nD+5GrsXQrzrBmYOv3ayyFwecwNr05umglbTX9bw2KrbvmPAv97OH114wOKTUa6F1\nWzWfAoGAasvUsT79g6BFLX5EI2wSi3LkYpkMKSuoI9ahwEnWrrYOHJS9ndqgJ62D\npIw1oI9vvZPxIA4j8qVeFi2Ks1VLwfXjCXZX/gXqKnDaVEDZPNsT/kaarO0OhaGv\noeeBTo3COjmZI1js3A0i3RiQtYsR8aRSCvS9ebaicGMXyTmECm0=\n-----END RSA PRIVATE KEY-----\n'
* private_key_scanner_10001 = <cryptography.hazmat.backends.openssl.rsa._RSAPrivateKey object at 0x000002271D3D7A00>
* bool(server_info_dict['server_private_key_base64'] == private_key_scanner_10001) = False
image_signed_hash_manifest_daf

| scanner_id | ballot_id |                          image_data_hex                          |                        image_hash_digest                         |                                 signature_base64                                 |
| ---------: | --------: | ---------------------------------------------------------------: | ---------------------------------------------------------------: | -------------------------------------------------------------------------------: |
|      10001 |     50001 | 41a627c41845efd584753d9d5e8481c17c2c2c943ae9d9cc2b3f9c095d983fbe | 8225811a7cb4a6ce3284d30ecc607be011d1c9e6d4d726c7143eb78a1f58cfcc | x7Atu/BXnwUs9/NErimM65Zo4KwXhSBXneEAeOY..cXICjHplKwDHjnZ8Ss6sLHlY11Q2rHhh/YlMQ== |
|      10001 |     50002 | 5be3cecc261202ade01588ea25fd4168dde65c56fe3b5993a9673eba06f7c222 | cc0939a36623d1ea94915981e4b51b8095e808bcadfb8cbd8042db922d00cc2d | r8dyZYfNKeEI2YwHq2vyl0GsGY2zBMJQAxbCmAF..uASVUFufFTSF5Fw7pkK/UajAk5ahrLeVzYLpQ== |
|      10001 |     50003 | 91764a10388528d0c4ae01525fc745301355731187cb29165b18daed9916abec | 220707306621a3f043d094444cb5585a5e77c03aa80448b8593b9d0a2195ab4c | CTVVYhmG/cR9pAJAsLtyEbDInbfKjrWiFaXO0UP..vyw5zRI6l3hx78yFQp5NMJzJIwJ18/DQEHkUA== |
|      10001 |     50004 | 5c307207ec93ccecb1444f2f369af06096bbb975aa49046ee5395f267f84ab36 | 711b5a034bab437624dfca51a78011f2f298b83a07db1f0c9f767bf25fdb109c | Ara7XMSo1R84EEjoKqPxBEvzxvGfKn5Tj20yWmc..jzJN/Jco7ouWaWu7sq3l3MJvvAVtZ7O9UxJgQ== |
|      10001 |     50005 | 3e179ceb3d5cc24036a43c1e0c36e9371cb6a282844608ba92a9c9e39c23b797 | 0e4435848c5b1eafe47557548c31a6d52ecb118c894ed34a8352741bada805a3 | l+h4tC6+avb6B9omzqu/Ok3BUTOl7JLHK6keC6r..dZgOCCt3JHo5zhEwt9zTTcmu1O8h3Zegot/kQ== |
|        ... |       ... |                                                              ... |                                                              ... |                                                                              ... |
|      10001 |     50016 | 2377ac4d8d2aa7a95d28af396396d7918331bf57520a0fafc5846690dc86b8d0 | 1cab7271ea4e98cf3290312e8adb0a113e297fc99f883833a8fbab62d5fe4105 | GzUx5Vj65EYle4TPHDqBHW7Gfvn5Bx7rIVL0Ltd..H9limDMDo2m8GuRd/QtTXrpKfU0flzQFrBWLA== |
|      10001 |     50017 | 840490b115abb2a6c0c73e26a42bab6d15e3df2131f8cb0eaa168b4712599ecd | c200eb627d64364f8ef9814b92f32c645a1ef3956bcb8208ff127b2264790122 | ejBD2yt4IsyHrG2ty1mWP8n/RNI4KSSavq9PPpN..Bs3UxcI1GZzgAXaG7yChPypXDK5pmHwB0jr6Q== |
|      10001 |     50018 | d0a0eea47dfef8e36c68f878e766b8b7dcff80ed9645baf4642a75c3f95657e9 | 8b2e28731d5b9905ee72d6444d68a6d0d00c2e23f821a58ae93778cc9b9c190b | UU8gK5l0XeX2TRuegitsJWjfQV0VPWwtYcRLIXF..e+b0E+AR7rH2APR1jfXs7rG0aJLnuSdeeCkdg== |
|      10001 |     50019 | dbfbd0c7acb3fc0e6b104090ff65dfea89e8c85dab2436494f1f70d4252fb680 | 5ee5dadac4551bae74d5118c9896b5b363c4cc306290b932589215d22229c35f | sHqp1ffLZhWvHuuHcUeD4aiDNk+jm//R448da/E..cTxt4cDyGQlktzmGsqVsnl7mGCLO8+bBHNPCA== |
|      10001 |     50020 | 323f168d61037d71b0fabeac656c71c28ea40cffedb20dc7b1649ab612263ef3 | 4e2f321d39ad25b5ba28731d33dd308ca31a20f10f7a494ff85eb8241d4ee726 | oxivJ/+H4xM/yFWGsolnPuxwGksTgxDcFLyv62k..Xz7q6mZ0j3oG1CcCyKrdE3pMM6wbZ2/Kao80Q== |

\[20 rows x 5 cols; keyfield=; 0 keys ] (Daf)



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
|      10001 |     50001 | 41a627c41845efd584753d9d5e8481c17c2c2c943ae9d9cc2b3f9c095d983fbe | 8225811a7cb4a6ce3284d30ecc607be011d1c9e6d4d726c7143eb78a1f58cfcc | x7Atu/BXnwUs9/NErimM65Zo4KwXhSBXneEAeOY..cXICjHplKwDHjnZ8Ss6sLHlY11Q2rHhh/YlMQ== |
|      10001 |     50002 | 5be3cecc261202ade01588ea25fd4168dde65c56fe3b5993a9673eba06f7c222 | cc0939a36623d1ea94915981e4b51b8095e808bcadfb8cbd8042db922d00cc2d | r8dyZYfNKeEI2YwHq2vyl0GsGY2zBMJQAxbCmAF..uASVUFufFTSF5Fw7pkK/UajAk5ahrLeVzYLpQ== |
|      10001 |     50003 | 91764a10388528d0c4ae01525fc745301355731187cb29165b18daed9916abec | 220707306621a3f043d094444cb5585a5e77c03aa80448b8593b9d0a2195ab4c | CTVVYhmG/cR9pAJAsLtyEbDInbfKjrWiFaXO0UP..vyw5zRI6l3hx78yFQp5NMJzJIwJ18/DQEHkUA== |
|      10001 |     50004 | 5c307207ec93ccecb1444f2f369af06096bbb975aa49046ee5395f267f84ab36 | 711b5a034bab437624dfca51a78011f2f298b83a07db1f0c9f767bf25fdb109c | Ara7XMSo1R84EEjoKqPxBEvzxvGfKn5Tj20yWmc..jzJN/Jco7ouWaWu7sq3l3MJvvAVtZ7O9UxJgQ== |
|      10001 |     50005 | 3e179ceb3d5cc24036a43c1e0c36e9371cb6a282844608ba92a9c9e39c23b797 | 0e4435848c5b1eafe47557548c31a6d52ecb118c894ed34a8352741bada805a3 | l+h4tC6+avb6B9omzqu/Ok3BUTOl7JLHK6keC6r..dZgOCCt3JHo5zhEwt9zTTcmu1O8h3Zegot/kQ== |
|        ... |       ... |                                                              ... |                                                              ... |                                                                              ... |
|      10001 |     50016 | 2377ac4d8d2aa7a95d28af396396d7918331bf57520a0fafc5846690dc86b8d0 | 1cab7271ea4e98cf3290312e8adb0a113e297fc99f883833a8fbab62d5fe4105 | GzUx5Vj65EYle4TPHDqBHW7Gfvn5Bx7rIVL0Ltd..H9limDMDo2m8GuRd/QtTXrpKfU0flzQFrBWLA== |
|      10001 |     50017 | 840490b115abb2a6c0c73e26a42bab6d15e3df2131f8cb0eaa168b4712599ecd | c200eb627d64364f8ef9814b92f32c645a1ef3956bcb8208ff127b2264790122 | ejBD2yt4IsyHrG2ty1mWP8n/RNI4KSSavq9PPpN..Bs3UxcI1GZzgAXaG7yChPypXDK5pmHwB0jr6Q== |
|      10001 |     50018 | d0a0eea47dfef8e36c68f878e766b8b7dcff80ed9645baf4642a75c3f95657e9 | 8b2e28731d5b9905ee72d6444d68a6d0d00c2e23f821a58ae93778cc9b9c190b | UU8gK5l0XeX2TRuegitsJWjfQV0VPWwtYcRLIXF..e+b0E+AR7rH2APR1jfXs7rG0aJLnuSdeeCkdg== |
|      10001 |     50019 | dbfbd0c7acb3fc0e6b104090ff65dfea89e8c85dab2436494f1f70d4252fb680 | 5ee5dadac4551bae74d5118c9896b5b363c4cc306290b932589215d22229c35f | sHqp1ffLZhWvHuuHcUeD4aiDNk+jm//R448da/E..cTxt4cDyGQlktzmGsqVsnl7mGCLO8+bBHNPCA== |
|      10001 |     50020 | 323f168d61037d71b0fabeac656c71c28ea40cffedb20dc7b1649ab612263ef3 | 4e2f321d39ad25b5ba28731d33dd308ca31a20f10f7a494ff85eb8241d4ee726 | oxivJ/+H4xM/yFWGsolnPuxwGksTgxDcFLyv62k..Xz7q6mZ0j3oG1CcCyKrdE3pMM6wbZ2/Kao80Q== |

\[20 rows x 5 cols; keyfield=; 0 keys ] (Daf)



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
|      10001 |     50001 | 41a627c41845efd584753d9d5e8481c17c2c2c943ae9d9cc2b3f9c095d983fbe | 8225811a7cb4a6ce3284d30ecc607be011d1c9e6d4d726c7143eb78a1f58cfcc | x7Atu/BXnwUs9/NErimM65Zo4KwXhSBXneEAeOY..cXICjHplKwDHjnZ8Ss6sLHlY11Q2rHhh/YlMQ== |
|      10001 |     50002 | 17d95460ba51cd7479293cb113e3d52035a52fc1b1980cfe6da052d9df57bbd1 | cc0939a36623d1ea94915981e4b51b8095e808bcadfb8cbd8042db922d00cc2d | r8dyZYfNKeEI2YwHq2vyl0GsGY2zBMJQAxbCmAF..uASVUFufFTSF5Fw7pkK/UajAk5ahrLeVzYLpQ== |
|      10001 |     50003 | 97845ff068aea910b4055a26c3caac101976a076d8ad1bcbb48474c874defbda | eb3f6f14a11781eca52206c160b302c84bf43020da45e7a77f07d6908877e292 | CTVVYhmG/cR9pAJAsLtyEbDInbfKjrWiFaXO0UP..vyw5zRI6l3hx78yFQp5NMJzJIwJ18/DQEHkUA== |
|      10001 |     50004 | 5c307207ec93ccecb1444f2f369af06096bbb975aa49046ee5395f267f84ab36 | 711b5a034bab437624dfca51a78011f2f298b83a07db1f0c9f767bf25fdb109c | Ara7XMSo1R84EEjoKqPxBEvzxvGfKn5Tj20yWmc..jzJN/Jco7ouWaWu7sq3l3MJvvAVtZ7O9UxJgQ== |
|      10001 |     50005 | 3e179ceb3d5cc24036a43c1e0c36e9371cb6a282844608ba92a9c9e39c23b797 | 0e4435848c5b1eafe47557548c31a6d52ecb118c894ed34a8352741bada805a3 | l+h4tC6+avb6B9omzqu/Ok3BUTOl7JLHK6keC6r..dZgOCCt3JHo5zhEwt9zTTcmu1O8h3Zegot/kQ== |
|        ... |       ... |                                                              ... |                                                              ... |                                                                              ... |
|      10001 |     50016 | 2377ac4d8d2aa7a95d28af396396d7918331bf57520a0fafc5846690dc86b8d0 | 1cab7271ea4e98cf3290312e8adb0a113e297fc99f883833a8fbab62d5fe4105 | GzUx5Vj65EYle4TPHDqBHW7Gfvn5Bx7rIVL0Ltd..H9limDMDo2m8GuRd/QtTXrpKfU0flzQFrBWLA== |
|      10001 |     50017 | 840490b115abb2a6c0c73e26a42bab6d15e3df2131f8cb0eaa168b4712599ecd | c200eb627d64364f8ef9814b92f32c645a1ef3956bcb8208ff127b2264790122 | ejBD2yt4IsyHrG2ty1mWP8n/RNI4KSSavq9PPpN..Bs3UxcI1GZzgAXaG7yChPypXDK5pmHwB0jr6Q== |
|      10001 |     50018 | d0a0eea47dfef8e36c68f878e766b8b7dcff80ed9645baf4642a75c3f95657e9 | 8b2e28731d5b9905ee72d6444d68a6d0d00c2e23f821a58ae93778cc9b9c190b | UU8gK5l0XeX2TRuegitsJWjfQV0VPWwtYcRLIXF..e+b0E+AR7rH2APR1jfXs7rG0aJLnuSdeeCkdg== |
|      10001 |     50019 | dbfbd0c7acb3fc0e6b104090ff65dfea89e8c85dab2436494f1f70d4252fb680 | 5ee5dadac4551bae74d5118c9896b5b363c4cc306290b932589215d22229c35f | sHqp1ffLZhWvHuuHcUeD4aiDNk+jm//R448da/E..cTxt4cDyGQlktzmGsqVsnl7mGCLO8+bBHNPCA== |
|      10001 |     50020 | 323f168d61037d71b0fabeac656c71c28ea40cffedb20dc7b1649ab612263ef3 | 4e2f321d39ad25b5ba28731d33dd308ca31a20f10f7a494ff85eb8241d4ee726 | oxivJ/+H4xM/yFWGsolnPuxwGksTgxDcFLyv62k..Xz7q6mZ0j3oG1CcCyKrdE3pMM6wbZ2/Kao80Q== |

\[20 rows x 5 cols; keyfield=; 0 keys ] (Daf)



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
* public_key_record['server_public_key_cbor_base64'] = 'WQHDLS0tLS1CRUdJTiBQVUJMSUMgS0VZLS0tLS0KTUlJQklqQU5CZ2txaGtpRzl3MEJBUUVGQUFPQ0FROEFNSUlCQ2dLQ0FRRUEyeGtkcExQbFFJMHUzYXRKVm9DTgp2citrZ0xBU3JabFpJckJ3OHlVZFczUEFXMjlNQ1JYeGE0ZXFUYlpzcDFCaEtuR3ZKTlQvYVNIenB5RmRzTlFtCnNESHRPTmFNU2tTQzBUVmlGdHhtSmNZTzdiUm82UEpBVUlMdTVzUzBYcXhSZmxZbHpITjFtSkhhSXdzMUhRZmcKNmIvSjVhYldzdUNZYUMrYVRScktiWUVLcDlHeURwR3ZSYWcrNXhvVlJaWno1VHhFRmlhT0JaRktyOXE1TWdNSApuc0FMR0lLVFF2TUdpR0dUS00yUXZiVFQ2alg4Znc2Y2F4NGpzMkNMVWhPdzhiRC9BMWNUK2ZTWUJQd0llVDI4Cm16VCt3RzNlbUs4Qm5aZE9BTkpkemQveTRXRG1KclcySWNBdVFEbFJZOU84Q1NoVlpTTnRwNnBkbG5mSG9KM2cKWFFJREFRQUIKLS0tLS1FTkQgUFVCTElDIEtFWS0tLS0tCg=='
* public_key_record['nonce_base64'] = '6aeH+ktvfPNfldzUiAYN6w82iUVmsNAJ8yBqpjs16yg='
* public_key_record['signed_nonce_base64'] = 'jSKWal2a/pkPn7TN40Ue0fAScp0qrItLfCyySjYOKSSrF6uSXv80laads7Tj0oB1q/n58xcyH2hga5f2dD72peNXJjrsr/GmdJMxZG5PvoZoI4I4sNk+1U71K+n99fuvUHQMvFrvH/qf8zLRFwfrN1YdbvBFeDNK78P/pJ4YAm1qhuyhrDB4HKiCUqw6xgg1pVeLwa+dRb8oQNshNR7Aouc1Lsox3KWMprMRsCFOahLTBVfH6LPtqaIxaw8cuSwtXz4BjVfPdTviqwXRrLQCSCaXXyPM2u0kU1HG4tdXBPGLjApv+IVhf3JScBB/qtEHpAL8PSfkvNQg2vrXyDloOg=='

## Check Images for consistency -- create independent hashes and signatures.

Here, we take the table of the image hash manifest and add three columns,
        
* 'calc_image_hash_digest'    -- this is the hash digest independently calculated from the image.
* 'is_hash_verified'          -- this is whether the hash calculated from the image matches that provided in the manifest.
* 'is_signature_verified'     -- verify the signature of the calculated hash using the scanner public key. 
        
This process would be repeated for each image from each scanner.

```python
    # create a new table with three new columns:
    calc_hash_manifest_daf = Daf(cols=image_signed_hash_manifest_daf.columns() + 
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
|      10001 |     50001 | 41a627c41845efd584753d9d5e8481c17c2c2c943ae9d9cc2b3f9c095d983fbe | 8225811a7cb4a6ce3284d30ecc607be011d1c9e6d4d726c7143eb78a1f58cfcc | x7Atu/BXnwUs9/NErimM65Zo4KwXhSBXneEAeOY..cXICjHplKwDHjnZ8Ss6sLHlY11Q2rHhh/YlMQ== | 3f11d8831b76105e0d6f33783378a00a9e4e5efde54f76e82b25075a94e0dc6d |            False |                 False |
|      10001 |     50002 | 17d95460ba51cd7479293cb113e3d52035a52fc1b1980cfe6da052d9df57bbd1 | cc0939a36623d1ea94915981e4b51b8095e808bcadfb8cbd8042db922d00cc2d | r8dyZYfNKeEI2YwHq2vyl0GsGY2zBMJQAxbCmAF..uASVUFufFTSF5Fw7pkK/UajAk5ahrLeVzYLpQ== | cce408377432ec19459a152b736e4db49415ebf82cb5857d65ce1e8fe0f8b38c |            False |                 False |
|      10001 |     50003 | 97845ff068aea910b4055a26c3caac101976a076d8ad1bcbb48474c874defbda | eb3f6f14a11781eca52206c160b302c84bf43020da45e7a77f07d6908877e292 | CTVVYhmG/cR9pAJAsLtyEbDInbfKjrWiFaXO0UP..vyw5zRI6l3hx78yFQp5NMJzJIwJ18/DQEHkUA== | 73f39ce3fd663bebee27a18e24c4e49690616c39227dace634074f26fab01af9 |            False |                 False |
|      10001 |     50004 | 5c307207ec93ccecb1444f2f369af06096bbb975aa49046ee5395f267f84ab36 | 711b5a034bab437624dfca51a78011f2f298b83a07db1f0c9f767bf25fdb109c | Ara7XMSo1R84EEjoKqPxBEvzxvGfKn5Tj20yWmc..jzJN/Jco7ouWaWu7sq3l3MJvvAVtZ7O9UxJgQ== | 084c86486782d0f4c65af946265b8341b168d82e613944290cd809927bff793e |            False |                 False |
|      10001 |     50005 | 3e179ceb3d5cc24036a43c1e0c36e9371cb6a282844608ba92a9c9e39c23b797 | 0e4435848c5b1eafe47557548c31a6d52ecb118c894ed34a8352741bada805a3 | l+h4tC6+avb6B9omzqu/Ok3BUTOl7JLHK6keC6r..dZgOCCt3JHo5zhEwt9zTTcmu1O8h3Zegot/kQ== | 052b2e76d749766257fea41bbbe9bc089089e8bf88f74c1f66353f8841864dd4 |            False |                 False |
|        ... |       ... |                                                              ... |                                                              ... |                                                                              ... |                                                              ... |              ... |                   ... |
|      10001 |     50016 | 2377ac4d8d2aa7a95d28af396396d7918331bf57520a0fafc5846690dc86b8d0 | 1cab7271ea4e98cf3290312e8adb0a113e297fc99f883833a8fbab62d5fe4105 | GzUx5Vj65EYle4TPHDqBHW7Gfvn5Bx7rIVL0Ltd..H9limDMDo2m8GuRd/QtTXrpKfU0flzQFrBWLA== | f49c80108b97e42b73e235012331b09fb9e44242ad60f561cfeec89bddbb7fa2 |            False |                 False |
|      10001 |     50017 | 840490b115abb2a6c0c73e26a42bab6d15e3df2131f8cb0eaa168b4712599ecd | c200eb627d64364f8ef9814b92f32c645a1ef3956bcb8208ff127b2264790122 | ejBD2yt4IsyHrG2ty1mWP8n/RNI4KSSavq9PPpN..Bs3UxcI1GZzgAXaG7yChPypXDK5pmHwB0jr6Q== | b97c18a51b4ea644fc9faf840175e191759028b700ab2d4a0574b29118fad284 |            False |                 False |
|      10001 |     50018 | d0a0eea47dfef8e36c68f878e766b8b7dcff80ed9645baf4642a75c3f95657e9 | 8b2e28731d5b9905ee72d6444d68a6d0d00c2e23f821a58ae93778cc9b9c190b | UU8gK5l0XeX2TRuegitsJWjfQV0VPWwtYcRLIXF..e+b0E+AR7rH2APR1jfXs7rG0aJLnuSdeeCkdg== | 39e26856dd912bd98a068933ebfbdaee1cad774e2ec8fa20838855c56e6dec2a |            False |                 False |
|      10001 |     50019 | dbfbd0c7acb3fc0e6b104090ff65dfea89e8c85dab2436494f1f70d4252fb680 | 5ee5dadac4551bae74d5118c9896b5b363c4cc306290b932589215d22229c35f | sHqp1ffLZhWvHuuHcUeD4aiDNk+jm//R448da/E..cTxt4cDyGQlktzmGsqVsnl7mGCLO8+bBHNPCA== | 1430dbfbd7425bcc7e65685b0e3866a364905368c332973aab48916daecf11f5 |            False |                 False |
|      10001 |     50020 | 323f168d61037d71b0fabeac656c71c28ea40cffedb20dc7b1649ab612263ef3 | 4e2f321d39ad25b5ba28731d33dd308ca31a20f10f7a494ff85eb8241d4ee726 | oxivJ/+H4xM/yFWGsolnPuxwGksTgxDcFLyv62k..Xz7q6mZ0j3oG1CcCyKrdE3pMM6wbZ2/Kao80Q== | 6d0f88a2c5886281e40f2a33a14ec2f146f3a785b90f6cdf3c92bee68127c869 |            False |                 False |

\[20 rows x 8 cols; keyfield=; 0 keys ] (Daf)


