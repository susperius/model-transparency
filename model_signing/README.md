# Model Signing

This project demonstrates how to protect the integrity of a model by signing it
with [Sigstore](https://www.sigstore.dev/), a tool for making code signatures
transparent without requiring management of cryptographic key material.

When users download a given version of a signed model they can check that the
signature comes from a known or trusted identity and thus that the model hasn't
been tampered with after training.

Signing events are recorded to Sigstore's append-only transparency log.
Transparency logs make signing events discoverable: Model verifiers can validate
that the models they are looking at exist in the transparency log by checking a
proof of inclusion (which is handled by the model signing library).
Furthermore, model signers that monitor the log can check for any unexpected
signing events.

Model signers should monitor for occurences of their signing identity in the
log. Sigstore is actively developing a [log
monitor](https://github.com/sigstore/rekor-monitor) that runs on GitHub Actions.

![Signing models with Sigstore](images/sigstore-model-diagram.png)

## Model Signing CLI

The `sign.py` and `verify.py` scripts aim to provide the necessary functionality
to sign and verify ML models. For signing and verification the following methods
are supported:

* Sigstore (sigstore.dev)
* Bring your own key pair
* Bring your own PKI
* Skip signing (only hash and create a bundle)

The signing part creates a [sigstore bundle](https://github.com/sigstore/protobuf-specs/blob/main/protos/sigstore_bundle.proto)
protobuf that is stored as in JSON format. The bundle contains the verification
material necessary to check the payload and a payload as a [DSSE envelope](https://github.com/sigstore/protobuf-specs/blob/main/protos/envelope.proto).
Further the DSSE envelope contains an in-toto statment and the signature over
that statement. The signature format and how the the signature is computed can
be seen [here](https://github.com/secure-systems-lab/dsse/blob/v1.0.0/protocol.md).

Finally, the statement itself contains subjects which are a list of (file path,
digest) pairs a predicate type set to `model_signing/v1/model`and a dictionary
f predicates. The idea is to use the predicates to store (and therefor sign) model
card information in the future.

The verification part reads the sigstore bundle file and firstly verifies that the
signature is valid and secondly compute the model's file hashes again to compare
against the signed ones.

### Usage

There are two scripts one can be used to create and sign a bundle and the other to
verify a bundle. Furthermore, the functionality can be used directly from other
Python tools. The `sign.py` and `verify.py` scripts can be used as canonical
how-to examples.

The easiest way to use the scripts directly is from a virtual environment:

```bash
$ python3 -m venv .venv
$ source .venv/bin/activate
(.venv) $ pip install -r install/requirements.in
```

## Sign

```bash
(.venv) $ python3 sign.py --model_path ${MODEL_PATH} --method {sigstore, private-key, pki} {additional parameters depending on method}
```

## Verify

```bash
(.venv) $ python3 verify.py --model_path ${MODEL_PATH} --method {sigstore, private-key, pki} {additional parameters depending on method}
```

### Examples

#### Bring Your Own Key

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

## Benchmarking

Install as per [Usage section](#usage).
Ensure you have enough disk space:
- if passing 3rd script argument as `true`: at least 50GB
- otherwise: at least 100GB

To run the benchmarks:

```bash
git clone git@github.com:sigstore/model-transparency.git
cd model-transparency/model_signing
bash benchmarks/run.sh https://accounts.google.com myemail@gmail.com [true]
```

A single run was performed.

Hashes used:
- H1: Hashing using a tree representation of the directory.
- H2: Hashing using a list representation of the directory. (Implementation is parallized with shards of 1GB sizes across vCPUs).

Machine M1: Debian 6.3.11 x86_64 GNU/Linux, 200GB RAM, 48 vCPUs, 512KB cache, AMD EPYC 7B12:

| Hash | Model              | Size  |  Sign Time | Verify Time |
|------|--------------------|-------|:------:|:-----:|
| H1 | roberta-base-11      | 8K    | 0.8s  | 0.6s  |
| H1 | hustvl/YOLOP         | 215M  | 1.2s  | 0.8s  |
| H1 | bertseq2seq          | 2.8G  | 4.6s  | 4.4s  |
| H1 | bert-base-uncased    | 3.3G  | 5s    | 4.7s  |
| H1 | tiiuae/falcon-7b     | 14GB  | 12.2s | 11.8s |
| H2 | roberta-base-11      | 8K    | 1s    | 0.6s  |
| H2 | hustvl/YOLOP         | 215M  | 1s    | 1s    |
| H2 | bertseq2seq          | 2.8G  | 1.9s  | 1.4s  |
| H2 | bert-base-uncased    | 3.3G  | 1.6s  | 1.1s  |
| H2 | tiiuae/falcon-7b     | 14GB  | 2.1s  | 1.8s  |

Machine M2: Debian 5.10.1 x86_64 GNU/Linux, 4GB RAM, 2 vCPUs, 56320 KB, Intel(R) Xeon(R) CPU @ 2.20GHz:

| Hash | Model              | Size  |  Sign Time | Verify Time |
|------|--------------------|-------|:------:|:-----:|
| H1 | roberta-base-11      | 8K    | 1.1s  | 0.7s  |
| H1 | hustvl/YOLOP         | 215M  | 1.9s  | 1.7s  |
| H1 | bertseq2seq          | 2.8G  | 18s   | 23.2s |
| H1 | bert-base-uncased    | 3.3G  | 23.4s | 18.9s |
| H1 | tiiuae/falcon-7b     | 14GB  | 2m4s | 2m2s   |
| H2 | roberta-base-11      | 8K    | 1.1s  | 0.8s  |
| H2 | hustvl/YOLOP         | 215M  | 1.9s  | 1.6s  |
| H2 | bertseq2seq          | 2.8G  | 13.8s | 25.9s |
| H2 | bert-base-uncased    | 3.3G  | 22.7s | 23.3s |
| H2 | tiiuae/falcon-7b     | 14GB  | 2m.1s | 2m3s  |

## Development steps

### Linting

`model_signing` is automatically linted and formatted with a collection of tools:

* [flake8](https://github.com/PyCQA/flake8)
* [pytype](https://github.com/google/pytype)

You can run the type checker locally by installing the `dev` dependencies:
```shell
python3 -m venv dev_env
source dev_env/bin/activate
os=Linux # Supported: Linux, Darwin.
python3 -m pip install --require-hashes -r "install/requirements_dev_${os}".txt
```

Then point pytype at the desired module or package:
```shell
pytype --keep-going model_signing/hashing
```
