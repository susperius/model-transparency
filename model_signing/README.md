# Model Signing

This project aims to provide the necessary functionality to sign and verify ML models.
For signing and verification the following methods are supported:

* Sigstore (sigstore.dev)
* Bring your own key pair
* Bring your own PKI
* Skip signing (only hash and create a bundle)

The signing part creates a [sigstore bundle](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto) 
protobuf that is stored as in JSON format. The bundle contains the verification material necessary to check the payload and a 
payload as a [DSSE envelope](https://github.com/sigstore/protobuf-specs/blob/main/protos/envelope.proto).
Further the DSSE envelope contains an in-toto statment and the signature over that statement. The signature format and how the
the signature is computed can be seen [here](https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md).

Finally, the statement itself contains subjects which are a list of (file path, digest) pairs a predicate type set to `model-signing/v1`
and a dictionary of predicates. The idea is to use the predicates to store (and therefor sign) model card information in the future.

The verification part reads the sigstore bundle file and firstly verifies that the signature is valid and secondly compute the model's
file hashes again to compare against the signed ones. 

# Usage

There are two scripts one can be used to create and sign a bundle and the other to verify a bundle. Furthermore, the functionality
can be used directly from other Python tools. The `sign.py` and `verify.py` scripts can be used as canonical how-to examples.

WARNING: `sigstore-python` must be installed from [head](https://github.com/sigstore/sigstore-python) locally until version 3.0 is released.

The easiest way to use the scripts directly is from a virtual environment:

```bash
$ python3 -m venv .venv
$ source .venv/bin/activate
(.venv) $ pip install -r requirements.txt
```

## Sign

```bash
(.venv) $ python3 sign.py --model_path ${MODEL_PATH} --method {sigstore, private-key, pki} {additional parameters depending on method}
```

## Verify

```bash
(.venv) $ python3 verify.py --model_path ${MODEL_PATH} --method {sigstore, private-key, pki} {additional parameters depending on method}
```

## Examples

### Bring Your Own Key

```bash
$ MODEL_PATH='/path/to/your/model'
$ openssl ecparam -name secp256k1 -genkey -noout -out ec-secp256k1-priv-key.pem
$ openssl ec -in ec-secp256k1-priv-key.pem -pubout > ec-secp256k1-pub-key.pem
$ source .venv/bin/activate
# SIGN
(.venv) $ python3 sign.py --model_path ${MODEL_PATH} --method private-key --private-key ec-secp256k1-priv-key.pem
...
#VERIFY
(.venv) $ python3 verify.py --model_path ${MODEL_PATH} --method private-key --public-key ec-secp256k1-pub-key.pem
...
```