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
"""This package provides the functionality to sign models"""

from typing import Optional

import abc

from absl import logging as log
from cryptography.hazmat.primitives import serialization as crypto_serialization
from cryptography.hazmat.primitives.asymmetric import ec as crypto_ec
from cryptography.hazmat.primitives.hashes import SHA256
from cryptography import x509 as crypto_x509
from google.protobuf import json_format
from in_toto_attestation.v1 import statement
from sigstore import dsse
from sigstore import oidc
from sigstore import sign
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb
from sigstore_protobuf_specs.dev.sigstore.common import v1 as common_pb
from sigstore_protobuf_specs.io import intoto as intoto_pb

from signature import utils


class Signer(abc.ABC):
    """Signer is the abstract base class for all signing methods."""

    @abc.abstractmethod
    def sign(self, stmnt: statement.Statement) -> bundle_pb.Bundle:
        """Sign signs the provide statment.

        Args:
            stmnt (statement.Statement): The statemnt that needs to be signed.

        Returns:
            bundle_pb.Bundle: Sigstore bundle containing the statement in a DSSE and the verification material.
        """


class FakeSigner(Signer):
    """Provides a Signer that just returns the bundle."""
    def sign(self, stmnt: statement.Statement) -> bundle_pb.Bundle:
        env = intoto_pb.Envelope(
            payload=json_format.MessageToJson(stmnt.pb).encode(),
            payload_type=utils.PAYLOAD_TYPE,
            signatures=[intoto_pb.Signature(sig=b'', keyid=None)],
        )
        bdl = bundle_pb.Bundle(
            media_type='application/vnd.dev.sigstore.bundle.v0.3+json',
            verification_material=bundle_pb.VerificationMaterial(
                public_key=common_pb.PublicKey(
                    raw_bytes=self._private_key.public_key().public_bytes(
                        encoding=crypto_serialization.Encoding.PEM,
                        format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
                    ),
                    key_details=common_pb.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
                ),
            ),
            dsse_envelope=env,
        )
        return bdl


class SigstoreSigner(Signer):
    """Provides a Signer that uses sigstore for signing."""

    CLIENT_ID = "sigstore"

    def __init__(self, disable_ambient: bool = True, id_provider: str = None):
        token = self.__get_identity_token(disable_ambient, id_provider)
        if not token:
            raise ValueError("No identity token supplied or detected!")
        log.info(f"Signing identity provider: {token.expected_certificate_subject}")
        log.info(f"Signing identity: {token.identity}")
        self._signer = sign.Signer(
            identity_token=token,
            signing_ctx=sign.SigningContext.production(),
        )

    @staticmethod
    def __convert_stmnt(stmnt: statement.Statement) -> dsse.Statement:
        subjects = stmnt.pb.subject
        sigstore_subjects = []
        for s in subjects:
            sigstore_subjects.append(
                dsse._Subject(
                    name=s.name,
                    digest={"sha256": s.digest["sha256"]},
                )
            )
        return dsse._StatementBuilder(
            predicate_type=stmnt.pb.predicate_type,
            predicate=stmnt.pb.predicate,
            subjects=sigstore_subjects,
        ).build()

    @staticmethod
    def __get_identity_token(
        disable_ambient: bool = True,
        id_provider: Optional[str] = None,
    ) -> Optional[oidc.IdentityToken]:
        token: oidc.IdentityToken
        if not disable_ambient:
            return oidc.detect_credential()

        issuer = oidc.Issuer(id_provider) if id_provider else oidc.Issuer.production()
        token = issuer.identity_token(
            client_id=SigstoreSigner.CLIENT_ID, force_oob=True
        )
        return token

    def sign(self, stmnt: statement.Statement) -> bundle_pb.Bundle:
        return self._signer.sign_dsse(self.__convert_stmnt(stmnt))._inner


class KeySigner(Signer):
    """Provides a Signer using an elliptic curve private key for signing."""

    def __init__(self, private_key_path: str, password: Optional[str] = None):
        self._private_key: crypto_ec.EllipticCurvePrivateKey
        with open(private_key_path, "rb") as fd:
            serialized_key = fd.read()
        self._private_key = crypto_serialization.load_pem_private_key(
            serialized_key, password=password
        )

    def sign(self, stmnt: statement.Statement) -> bundle_pb.Bundle:
        pae = utils.pae(stmnt.pb)
        sig = self._private_key.sign(pae, crypto_ec.ECDSA(SHA256()))
        env = intoto_pb.Envelope(
            payload=json_format.MessageToJson(stmnt.pb).encode(),
            payload_type=utils.PAYLOAD_TYPE,
            signatures=[intoto_pb.Signature(sig=sig, keyid=None)],
        )
        bdl = bundle_pb.Bundle(
            media_type='application/vnd.dev.sigstore.bundle.v0.3+json',
            verification_material=bundle_pb.VerificationMaterial(
                public_key=common_pb.PublicKey(
                    raw_bytes=self._private_key.public_key().public_bytes(
                        encoding=crypto_serialization.Encoding.PEM,
                        format=crypto_serialization.PublicFormat.SubjectPublicKeyInfo,
                    ),
                    key_details=common_pb.PublicKeyDetails.PKIX_ECDSA_P256_SHA_256,
                ),
            ),
            dsse_envelope=env,
        )

        return bdl


class PKISigner(Signer):
    """Provides a Signer using an elliptic curve private key for signing and
    adds the provided certificate information as verification material."""

    def __init__(
        self, private_key_path: str, signing_cert_path: str, cert_chain_paths: list[str]
    ) -> None:
        self._key_signer = KeySigner(private_key_path)
        self._signing_cert = utils.load_single_cert(signing_cert_path)

        pub_key = self._key_signer._private_key.public_key() 
        cert_pub_key = self._signing_cert.public_key() 
        if pub_key != cert_pub_key:
            raise ValueError('the private key\'s public key does not match the signing certificates public key')
        self._cert_chain = utils.load_multiple_certs(cert_chain_paths)

    @staticmethod
    def __chain(
        signing_cert: crypto_x509.Certificate, chain: list[crypto_x509.Certificate]
    ) -> list[common_pb.X509Certificate]:
        result_chain = [
            common_pb.X509Certificate(
                raw_bytes=signing_cert.public_bytes(
                    encoding=crypto_serialization.Encoding.DER,
                )
            )
        ]
        for cert in chain:
            result_chain.append(
                common_pb.X509Certificate(
                    raw_bytes=cert.public_bytes(
                        encoding=crypto_serialization.Encoding.DER,
                    )
                )
            )
        return result_chain

    def sign(self, stmnt: statement.Statement) -> bundle_pb.Bundle:
        bdl = self._key_signer.sign(stmnt)
        bdl.verification_material.public_key = None
        bdl.verification_material.x509_certificate_chain = (
            common_pb.X509CertificateChain(
                certificates=self.__chain(self._signing_cert, self._cert_chain)
            )
        )
        return bdl
