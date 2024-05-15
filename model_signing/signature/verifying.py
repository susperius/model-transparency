# Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""This package provides the functionality to verify signed models."""
from typing import Optional

import abc

from dataclasses import dataclass

import certifi

from cryptography import x509 as crypto_x509
from cryptography.x509 import oid as crypto_oid
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
from cryptography.hazmat.primitives.hashes import SHA256
from OpenSSL import crypto as ssl_crypto
from google.protobuf import json_format
from in_toto_attestation.v1 import statement_pb2 as statement_pb
from sigstore.verify import verifier as sig_verifier
from sigstore.verify import policy as sig_policy
from sigstore.verify import models as sig_models
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb

from signature import utils


@dataclass
class VerificationResult:
    passed: bool
    information: str = ''

class Verifier(abc.ABC):
    """Verifier is the abstract base class for all verifying methods."""

    @abc.abstractmethod
    def verify(self, bundle: bundle_pb.Bundle) -> VerificationResult:
        """Verify the signature of the provided bundle.

        Args:
            bundle (bundle_pb.Bundle): the bundle that needs to be verified.

        Returns:
            VerificationResult: status information about the verification.
        """
        pass

class FakeVerifier(Verifier):
    """Provides a fake verifier that always passes."""
    def verify(self, bundle: bundle_pb.Bundle) -> VerificationResult:
        return VerificationResult(passed=True)

class SigstoreVerifier(Verifier):
    """Provides a verifier using sigstore."""

    def __init__(self, oidc_provider: str, identity: str):
        self._verifier = sig_verifier.Verifier.production()
        self._policy = sig_policy.Identity(
            identity=identity,
            issuer=oidc_provider,
        )

    def verify(self, bundle: bundle_pb.Bundle) -> VerificationResult:
        try:
            sig_bundle = sig_models.Bundle(bundle)
            payload = self._verifier.verify_dsse(sig_bundle, self._policy)
        except Exception as e:
            return VerificationResult(passed=False, information=str(e))
        return VerificationResult(passed=True, information='')

class KeyVerifier(Verifier):
    """Provides a verifier using a public key."""

    def __init__(self, public_key: crypto_ec.EllipticCurvePublicKey):
        self._public_key = public_key
    
    @classmethod
    def from_path(cls, key_path: str):
        with open(key_path, 'rb') as fd:
            serialized_key = fd.read()
        public_key = crypto_serialization.load_pem_public_key(serialized_key)
        return cls(public_key)

    def verify(self, bundle: bundle_pb.Bundle) -> VerificationResult:
        statement = json_format.Parse(bundle.dsse_envelope.payload, statement_pb.Statement())
        pae = utils.pae(statement)
        try:
            self._public_key.verify(bundle.dsse_envelope.signatures[0].sig, pae, crypto_ec.ECDSA(SHA256()))
        except Exception as e:
            return VerificationResult(passed=False, information='signature verification failed ' + str(e))
        return VerificationResult(passed=True)
        

class PKIVerifier(Verifier):
    """Provides a verifier based on root certificates."""

    def __init__(self, 
                 root_certs: Optional[list[str]]=None) -> None:
        crypto_trust_roots: list[crypto_x509.Certificate] = []
        if root_certs:
            crypto_trust_roots = utils.load_multiple_certs(root_certs)
        else:
            crypto_trust_roots = utils.load_multiple_certs([certifi.where()])
        
        print(crypto_trust_roots[0].subject)
        self._store = ssl_crypto.X509Store()
        for c in crypto_trust_roots:
            self._store.add_cert(ssl_crypto.X509.from_cryptography(c))
        
    
    def verify(self, bundle: bundle_pb.Bundle) -> VerificationResult:
        signing_chain = bundle.verification_material.x509_certificate_chain
        signing_cert_crypto =crypto_x509.load_der_x509_certificate(
            signing_chain.certificates[0].raw_bytes)
        
        # TODO: two paths one with signed timestamp and one without (failing if system time not valid anymore)
        sign_time = signing_cert_crypto.not_valid_before_utc
        self._store.set_time(sign_time)
        signing_cert_ossl = ssl_crypto.X509.from_cryptography(signing_cert_crypto)
        chain = []
        for cert in signing_chain.certificates[1:]:
            chain.append(
                ssl_crypto.X509.from_cryptography(
                    crypto_x509.load_der_x509_certificate(cert.raw_bytes)
                )
            )
        
        store_ctx = ssl_crypto.X509StoreContext(self._store, signing_cert_ossl, chain)
        try:
            store_ctx.verify_certificate()
        except ssl_crypto.X509StoreContextError as err:
            return VerificationResult(
                passed=False,
                information=f'signing certificate verification failed: {err}')
        usage = signing_cert_crypto.extensions.get_extension_for_class(crypto_x509.KeyUsage)
        if not usage.value.digital_signature:
            return VerificationResult(
                passed=False, information='the certificate is not valid for digital signature usage')
        ext_usage = signing_cert_crypto.extensions.get_extension_for_class(crypto_x509.ExtendedKeyUsage)
        if not crypto_oid.ExtendedKeyUsageOID.CODE_SIGNING in ext_usage.value:
            return VerificationResult(
                passed=False, information='the certificate is not valid for code signing usage')
        
        # Verify the contents with a key verifier
        pub_key: crypto_ec.EllipticCurvePublicKey = signing_cert_crypto.public_key
        verifier = KeyVerifier(pub_key)
        return verifier.verify(bundle)