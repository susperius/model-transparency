# Copyright 2024 The Sigstore Authors
# Copyright (c) 2024, NVIDIA CORPORATION.  All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
import pathlib

from google.protobuf import json_format
from in_toto_attestation.v1 import statement
from in_toto_attestation.v1 import statement_pb2 as statement_pb
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb

from model_signing.manifest import in_toto
from model_signing.signature import signing
from model_signing.signature import verifying
from model_signing.serialization import serialization


def sign(model_path: pathlib.Path,
         signer: signing.Signer,
         serializer: serialization.Serializer,
         ignore_paths: list[str] = [],
         ) -> bundle_pb.Bundle:
    """Signs a model and returns a sigstore bundle.

    Args:
        model_path (pathlib.Path): Path to the model
        signer (signing.Signer): Signer to sign the statement
        serializer (serialization.Serializer): Serializer used to serialize the model
        ignore_paths (list[str], optional): Filenames that should be ignored during serialization. Defaults to [].

    Returns:
        bundle_pb.Bundle: Sigstore bundle containing a signed DSSE envelope
    """
    manifest = serializer.serialize(model_path, ignore_paths)
    stmnt = in_toto.manifest_to_statement(manifest)
    bundle = signer.sign(stmnt)
    return bundle


def verify(bundle: bundle_pb.Bundle,
           verifier: verifying.Verifier,
           model_path: pathlib.Path,
           serializer: serialization.Serializer,
           ignore_paths: list[str] = []):
    """Verifies the bundle information in comparison with the local model.

    Args:
        bundle (bundle_pb.Bundle): Sigstore bundle describing the model
        verifier (verifying.Verifier): Verifier to verify the signature
        model_path (pathlib.Path): Path to the local model.
        serializer (serialization.Serializer): Serializer to be used for the local model.
        ignore_paths (list[str], optional): Filenames to ignore during serialization. Defaults to [].

    Raises:
        verifying.VerificationError: on verification failures.
    """
    verifier.verify(bundle)
    local_manifest = serializer.serialize(model_path, ignore_paths)
    payload = bundle.dsse_envelope.payload
    peer_statment_pb = json_format.Parse(payload, statement_pb.Statement())
    peer_statment = statement.Statement.copy_from_pb(peer_statment_pb)
    peer_manifest = in_toto.statement_to_manifest(peer_statment)

    if peer_manifest != local_manifest:
        raise verifying.VerificationError('the manifest do not match')
