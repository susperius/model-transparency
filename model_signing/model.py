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
"""This package provides functionality to sign and verify models."""
from dataclasses import dataclass

from google.protobuf import json_format
from in_toto_attestation.v1 import statement_pb2 as statement_pb
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb

from hashing import model_hash
from signature.signing import Signer
from signature.verifying import Verifier

SUPPORTED_METHODS = ['sigstore', 'private-key', 'pki', 'skip']
STATEMENT_FAILURE = 'STATEMENT_FAILURE'
SIGNATURE_FAILURE = 'SIGNATURE_FAILURE'
SUBJECT_FAILURE = 'SUBJECT_FAILURE'


@dataclass
class ModelVerificationResult:
    passed: bool
    information: dict[str, str]


def __load_bundle(path: str) -> bundle_pb.Bundle:
    with open(path, 'r') as fd:
        data = fd.read()
    bundle = bundle_pb.Bundle().from_json(value=data)
    return bundle


def store_bundle(bundle: bundle_pb.Bundle, path: str):
    with open(path, 'w') as fd:
        fd.write(bundle.to_json())


def sign_model(model_path: str, signer: Signer) -> bundle_pb.Bundle:
    statement = model_hash.hash_model(model_path)
    return signer.sign(statement)


def __compare_subjects(
    signature: statement_pb.Statement, local: statement_pb.Statement
) -> tuple[bool, str]:
    sub_a = {}
    sub_b = {}
    for s in signature.subject:
        if not 'sha256' in s.digest.keys():
            return False, f'no sha256 digest found for {s.name}'
        sub_a[s.name] = s.digest['sha256']
    for s in local.subject:
        if not 'sha256' in s.digest.keys():
            return False, f'no sha256 digest found for {s.name}'
        sub_b[s.name] = s.digest['sha256']

    if len(sub_a) != len(sub_b):
        return (
            False,
            f'the number of subjects isn\'t equal signature {len(sub_a)} vs local {len(sub_b)}',
        )

    for k, v in sub_a.items():
        
        if v != sub_b[k]:
            return False, f'hash mismatch for {k}'
    return True, ''


def verify_model(
    bundle_path: str, local_model_path: str, verifier: Verifier
) -> ModelVerificationResult:
    result = ModelVerificationResult(passed=False, information={})
    bundle = __load_bundle(bundle_path)
    signature_verification_result = verifier.verify(bundle)
    if not signature_verification_result.passed:
        result.passed = False
        result.information[SIGNATURE_FAILURE] = (
            signature_verification_result.information
        )
        return result

    payload = bundle.dsse_envelope.payload
    peer_statement = json_format.Parse(payload, statement_pb.Statement())
    local_statement = model_hash.hash_model(local_model_path)
    result.passed, info = __compare_subjects(peer_statement, local_statement.pb)
    if not result.passed:
        result.information[SUBJECT_FAILURE] = info
    return result
