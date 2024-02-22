# scitt_demo.py

# copyright (c) 2024 Ray Lutz



import os
import pprint

import sys
sys.path.append('..')

from Pydf.Pydf.md_demo import md_code_seg, pr 
from Pydf.Pydf import Pydf as daf

import base64
import cbor2  # CBOR library
import hashlib
from cryptography.exceptions                    import InvalidSignature
from cryptography.hazmat.primitives             import hashes, serialization
from cryptography.hazmat.primitives.asymmetric  import padding
from cryptography.hazmat.primitives.asymmetric  import rsa
from cryptography.hazmat.backends               import default_backend


def write_md_demo(md_report):
    sep = os.sep
    try:
        os.mkdir("docs")
    except Exception:
        pass
    
    if sep == '/':
        md_path = 'docs/scitt_demo.md'
    else:
        md_path = r'docs\scitt_demo.md'
    

    with open(md_path, 'w') as file:
        file.write(md_report)


def main():

    md_report = "# SCITT Demo for Election Data Security\n\n"
    
    md_report += md_code_seg('Introduction')
    """ SCITT -- Supply Chain Integrity, Transparancy and Trust may be used for election data security.
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
    
"""

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


    md_report += md_code_seg("Define a function to generate hash digests")
    """ To secure this file, we need to create a hash digest of the csv file.
        Therefore, we need a function to generate say a sha256 hash digest of
        the file. The algorithm and number of bits can be changed needed.
    """
    
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


    md_report += md_code_seg("Code to create and check digital signatures.")
    """ We also need to be able to cryptographicaly "sign" data using the private key,
        and to check those signatures. The 'sign_data' function accepts some data
        and signs it with the private key, creating a digital signature in base64 format.
        
The verify signature function accepts a signature in base64 encoding and
        verifies it.
        
We also need to be able to generate a random number which will be used only once.
        This is traditionally called a nonce.
        
    """
    
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
        
    
    md_report += md_code_seg("Verify Signature")
    """ We assume that the public_key_request can be appropriately and securely
        transmitted to the scanner device using thumbdrives. The Scanner checks the
        proof that the EMS has the associated private key based on the request.
        For that we need to have a function for checking a signature.
    """
    
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
    

    md_report += md_code_seg("Generate EMS private and public keys as Base64.")
    """ It is essential to acquire the public key from each scanner. 
        Unfortunately RATS, the Remote Attestation protocol for IOT devices does not
        provide such a request. Therefore, we will design our own.
        
First, we need to have a EMS Public and Private key.
    """

    client_private_key, client_public_key_cbor_base64 = generate_random_key_pair_base64()
    
    client_private_key_base64 = private_key_to_base64(client_private_key)

    md_report += pr(f"{client_private_key_base64 = }\n\n{client_public_key_cbor_base64 = }\n\n")

    md_report += md_code_seg("Create a request for the scanner's public key")
    """ The request for the scanner's public key can be provided to the device using a
        secure communication protocol with USB thumbdrives. The protocol will not be
        described here, but the data transferred using USB thumbdrives will be further
        encrypted so it will not be possible to view or alter the data on the thumbdrive if it is
        intercepted. For purposes of this proof of concept, we can assume this is a 
        reliable channel.
        
The request of the scanner's public key will include the public key of the 
        EMS and a nonce, which is further signed by the EMS, to provide proof that the
        public key is associated with the EMS's private key. 
    """
    
    nonce = generate_nonce()
    signed_nonce_base64 = sign_data_to_base64(nonce, client_private_key)
    
    public_key_request = {
        'client_public_key_cbor_base64': client_public_key_cbor_base64,
        'nonce_base64'            : to_base64(nonce),
        'signed_nonce_base64'     : signed_nonce_base64
        }
        
    # the request:
    md_report += pr(f"public_key_request:\n\n{pprint.pformat(public_key_request)}\n\n")
        
    md_report += md_code_seg("Scanner checks request")
    """ With that function available, we can now check that the request is well-formed.
    
    """
    
    # verify that the request is well-formed.
    if not verify_signature(
            signature_base64        = public_key_request['signed_nonce_base64'], 
            data                    = from_base64(public_key_request['nonce_base64']), 
            public_key_cbor_base64  = public_key_request['client_public_key_cbor_base64']):
            
        validation_str = "Error: public_key is NOT consistent with the signed nonce."    
    else:
        validation_str = "Success: public_key is consistent with the signed nonce."    
    
    md_report += pr(validation_str) + "\n\n"
    
    md_code_seg()    # end marker
    write_md_demo(md_report)

    md_report += md_code_seg("Scanner creates a response.")
    """ The scanner acts as a server and creates a response by creating a key pair, 
        and signs the nonce and returns the signature of the nonce.
    """

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
        
    md_report += md_code_seg("Client checks the response.")
    """ The EMS checks the response to validate the server_public_key.
    """
    
    # verify that the response is well-formed.
    if not verify_signature(
            signature_base64        = scanner_response['signed_nonce_base64'], 
            data                    = from_base64(scanner_response['nonce_base64']), 
            public_key_cbor_base64  = scanner_response['server_public_key_cbor_base64']):
            
        validation_str = "Error: public_key is NOT consistent with the signed nonce."    
    else:
        validation_str = "Success: public_key is consistent with the signed nonce."    
     
    md_report += pr(validation_str) + "\n\n" 
     
    md_report += md_code_seg("Process is repeated for all 500 scanners.")
    """ We can simulate that this process is repeated for all scanners.
        The client builds a `public_key_manifest` for all scanners, and
        we can track what is inside each scanner as the `server_internal_info`
        Here, for expediency, we will simulate only 20 scanners.
    """
    
   
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
    
    md_report += md_code_seg("Save public_key_manifest.csv.")
    """ Now save these two files. The first file, 'public_key_manifest.csv' will be saved to a csv file,
        and we will further commit this file to a transparancy service so it cannot be altered after the fact.
        When converting to a csv buffer, we use CRLF as line endings regardless of the platform for consistency.
    """
    public_key_manifest_buff = public_key_manifest_daf.to_csv_buff()
    # we need the buffer so we can create the hash value momentarily.
    try:
        daf.Pydf.buff_to_file(public_key_manifest_buff, "public_key_manifest.csv")
    except Exception as err:
        print(err)
        import pdb; pdb.set_trace() #temp
        pass
        
    server_internal_info_daf.to_csv_file("server_internal_info.csv")
    
    md_report += md_code_seg("Generate a hash digest of public_key_manifest")
    """ Use the function to generate the hash value.
    """

    public_key_manifest_sha256_hash_digest = generate_sha256_hash(public_key_manifest_buff)
    
    md_report += pr(f"{public_key_manifest_sha256_hash_digest =}")
    
    md_report += md_code_seg("Set up an append-only log using merkle tree")
    """ Now, given the hash, we need to submit that to a SCITT transparancy service.
        to simulate the service, we will set up a merkle-tree using pymerkle package.
        
According to SCITT architecture document: 

The Append-only Log is empty when the Transparency Service 
is initialized. The first entry that is added to the Append-only Log MUST be a Signed Statement 
including key material. The second set of entries are Signed Statements for additional domain-specific 
Registration Policy. The third set of entries are Signed Statements for Artifacts. From here on a 
Transparency Service can check Signed Statements on registration via policy (that is at minimum, 
key material and typically a Registration Policy) and is therefore in a reliable state to register 
Signed Statements about Artifacts or a new Registration Policy.
              
    """   
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
    
    md_report += md_code_seg("Submit the public_key_manifest to the Merkle Tree log.")
    """ Now that the Merkle Tree is initialized, we can add the first entry, the
        public_key_manifest_sha256_hash_digest.
        
The creation of a Merkle Tree here is to allow review of SCITT architecture standards 
but in actual practice, the public_key_manifest would be sumitted to an established SCITT
transparency service.
        
    """
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
    
    md_code_seg()    # end marker
    write_md_demo(md_report)

    md_report += md_code_seg("Next we will simulate getting ballot signed hash manifest.")
    """ At this point, all the public keys of the installed ballot scanners are posted, 
        and submitted to the SCITT transparency service. The public_key_manifest should also
        be published to a posting service so anyone can download it. This should all happen
        well before the election occurs.
        
Later in the election, the voting system scanners are used to scan individual ballots, 
typically creating one or two image files per ballot. We will consider that one TIFF file
will be created per ballot with two pages each, and the entire Tiff file will be hashed to
create a hash value, and then the scanner will sign the hash value with its private key.

For purposes of this simulation, we will generate hash digests for random numbers that we
will generate, where the random number is a stand-in for the ballot image file. Here, we
will only be considering the first scanner in our list, with server_id '10001'.

From the perspective of the voting system scanner, it has its own private key, which is
actually not available for inspection, and a public key, which has already been provided
and included in the public_key_manifest.

For review, we will first pull out these values to simulate one scanner:
    """
    
    # cryptographic data for scanner 10001
    server_info_dict = server_internal_info_daf.irow(0)
    
    md_report += pr(f"* {server_info_dict['server_id'] = }\n")
    md_report += pr(f"* {server_info_dict['server_public_key_cbor_base64'] = }\n")
    md_report += pr(f"* {server_info_dict['server_private_key_base64'] = }\n")
    
    md_report += pr(f"* {private_key_scanner_10001 = }\n")

    md_report += pr(f"* {bool(server_info_dict['server_private_key_base64'] == private_key_scanner_10001) = }\n")
    
    #server_info_dict['server_private_key_base64'] = private_key_scanner_10001
    
    # Generate simulated hash digest values for the images.
    
    num_ballots = 20
    first_ballot_id = 50001
    #server_private_key = from_base64(server_info_dict['server_private_key_base64'])
    
    image_signed_hash_manifest_daf = daf.Pydf(cols=['scanner_id', 'ballot_id', 'image_data_hex', 'image_hash_digest', 'signature_base64'])
    
    for ballot_id in range(first_ballot_id, first_ballot_id + num_ballots):
        
        binary_image_data = generate_nonce(length=32)       # random data to simulate image data.
        
        image_hash_digest = generate_sha256_hash(binary_image_data)
        
        image_hash_signature_base64 = sign_data_to_base64(
                                        image_hash_digest, 
                                        private_key_scanner_10001
                                        )
        
        image_signed_hash_manifest_daf.append({
            'scanner_id':           '10001',
            'ballot_id':            ballot_id,
            'image_data_hex':       binary_image_data.hex(),
            'image_hash_digest':    image_hash_digest,
            'signature_base64':     image_hash_signature_base64,
            })
            
    md_report += pr(f"image_signed_hash_manifest_daf\n\n{image_signed_hash_manifest_daf}\n\n")      
    
    md_report += md_code_seg("Next we will simulate getting ballot signed hash manifest.")
    """ This simulation of the data returned from the ballot scanners is a bit different from
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
    """
    # the following simulates the idea that we have all the images, the hashes, and signatures in the image arhives.
    image_signed_hash_manifest_csv = image_signed_hash_manifest_daf.to_csv_buff()
    
    image_archive_hash_digest   = generate_sha256_hash(image_signed_hash_manifest_csv)
    
    scitt_log_index             = scitt_log.append_entry(image_archive_hash_digest.encode('utf-8'))

    # more is needed here to demonstrate how we can check this with the scitt instance.
    
    md_report += md_code_seg("Recover signed hash manifest as a table.")
    """ It is very important that we can check that ballot images have not been altered since 
        they were first scanned. We will simulate that here by assuming that we have
        obtained the ballot images as a ZIP archive, and we have gathered up the 
        hash digest and signature for each image from the file.
        
The result of that operation will be to obtain the following:
    
    """
    
    md_report += pr(f"image_signed_hash_manifest_daf\n\n{image_signed_hash_manifest_daf}\n\n") 

    md_report += md_code_seg("Simulate hacked ballot image files.")
    """ To test that the cryptographic protection will actually catch changed values, 
        we will simulate that the second image has been altered by a hacker after the
        security data was generated, but he changed nothing else.
        
In the case of the third image, we will simulate that the hacker also modified
        the image, and also was sophisticated and altered the hash value as well
        so it matches the altered ballot image data.
        
The hacker can't generate a new signature successfully because he does not have the 
private key generated inside the scanner in both cases.

The new table shows the changed image data but it does have a corresponding hash value
which is easily generated by the hacker to be consistent with the changed imaged data.
    
    """
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
    
    md_report += md_code_seg("Check Images for consistency -- Recover server public key.")
    """ to check the images for consistency, we need to be able to recover the scanner's public key
        from the public key manifest. In this simulation, we need only to have the first record from
        the public_key_manifest file, because we are workign with the data from the first scanner only.
    """
    
    public_key_record = public_key_manifest_daf.irow(0)
    server_public_key_cbor_base64 = public_key_record['server_public_key_cbor_base64']
    
    md_report += pr(f"* {public_key_record['server_id'] = }\n")
    md_report += pr(f"* {public_key_record['server_public_key_cbor_base64'] = }\n")
    md_report += pr(f"* {public_key_record['nonce_base64'] = }\n")
    md_report += pr(f"* {public_key_record['signed_nonce_base64'] = }\n")
    
    md_report += md_code_seg("Check Images for consistency -- create independent hashes and signatures.")
    """ Here, we take the table of the image hash manifest and add three columns,
        
* 'calc_image_hash_digest'    -- this is the hash digest independently calculated from the image.
* 'is_hash_verified'          -- this is whether the hash calculated from the image matches that provided in the manifest.
* 'is_signature_verified'     -- verify the signature of the calculated hash using the scanner public key. 
        
This process would be repeated for each image from each scanner.
        
    """
    
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
    
    
    md_code_seg()    # end marker
    #===================================

    write_md_demo(md_report)


if __name__ == '__main__':
    main()    