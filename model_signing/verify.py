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
"""This script can be used to verify model signatures."""
import pathlib

from absl import app
from absl import logging as log
from absl import flags
from sigstore_protobuf_specs.dev.sigstore.bundle import v1 as bundle_pb

from model_signing import model
from model_signing.hashing import file
from model_signing.hashing import memory
from model_signing.serialization import serialize_by_file
from model_signing.signature import SUPPORTED_METHODS
from model_signing.signature import verifying
from model_signing.signature import key
from model_signing.signature import pki
from model_signing.signature import sigstore
from model_signing.signature import fake


_SIG = flags.DEFINE_string('sig_path', '', 'the path to the signature')
_PATH = flags.DEFINE_string(
    'model_path', '', 'the path to the model\'s base folder.')
_METHOD = flags.DEFINE_enum(
    'method', None, SUPPORTED_METHODS,
    'the signing method to use.')

# Sigstore flags
_ID_PROVIDER = flags.DEFINE_string(
    'id_provider', '', 'URL to the ID provider', required=False)
_ID = flags.DEFINE_string(
    'id', '', 'the identity that is expected to have signed the model.',
    required=False)
# bring your own key flag
_KEY_PATH = flags.DEFINE_string(
    'public_key', '', 'the path to the public key used for verifying',
    required=False)
# bring your own PKI flag
_ROOT_CERTS = flags.DEFINE_list(
    'root_certs', None,
    ('paths to pem encoded certifcate files or single ',
     'file containing used as the root of trust'),
    required=False
)


def __check_sigstore_flags():
    if _ID.value == '' or _ID_PROVIDER.value == '':
        log.error(
            '--id_provider and --id are required for sigstore verification')
        exit()


def __check_private_key_flags():
    if _KEY_PATH.value == '':
        log.error('--public_key must be defined')
        exit()


def __check_pki_flags():
    if not _ROOT_CERTS.value:
        log.warning('no root of trust is set using system default')


def main(_):
    verifier: verifying.Verifier
    log.info(f'Creating verifier for {_METHOD.value}')
    if _METHOD.value == 'sigstore':
        __check_sigstore_flags()
        verifier = sigstore.SigstoreVerifier(
            _ID_PROVIDER.value, _ID.value)
    elif _METHOD.value == 'private-key':
        __check_private_key_flags()
        verifier = key.ECKeyVerifier.from_path(
            _KEY_PATH.value)
    elif _METHOD.value == 'pki':
        __check_pki_flags()
        verifier = pki.PKIVerifier.from_paths(
            _ROOT_CERTS.value)
    elif _METHOD.value == 'skip':
        verifier = fake.FakeVerifier()
    else:
        raise ValueError(f'unsupported signing method {_METHOD.value}')

    log.info(f'Verifying model signature from {_PATH.value}')

    sig_path = pathlib.Path(_SIG.value)
    bundle = bundle_pb.Bundle().from_json(
        value=sig_path.read_text())

    def hasher_factory(file_path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(
            file=file_path,
            content_hasher=memory.SHA256(),
        )

    serializer = serialize_by_file.FilesSerializer(
        file_hasher_factory=hasher_factory)

    try:
        model.verify(
            bundle=bundle,
            verifier=verifier,
            model_path=pathlib.Path(_PATH.value),
            serializer=serializer,
            ignore_paths=[sig_path.name])
    except verifying.VerificationError as err:
        log.error(f'verification failed: {err}')

    log.info('all checks passed')


if __name__ == '__main__':
    app.run(main)
