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
"""This script can be used to verify model signatures."""

import model

from absl import app
from absl import logging as log
from absl import flags

from signature import verifying


_SIG = flags.DEFINE_string('sig_path', '', 'the path to the signature')
_PATH = flags.DEFINE_string('model_path', '', 'the path to the model\'s base folder.')
_METHOD = flags.DEFINE_enum('method', None, model.SUPPORTED_METHODS, 'the signing method to use.')

# Sigstore flags
_ID_PROVIDER = flags.DEFINE_string(
    'id_provider', '', 'URL to the ID provider', required=False)
_ID = flags.DEFINE_string(
    'id', '', 'the identity that is expected to have signed the model.', required=False)
# bring your own key flag
_KEY_PATH = flags.DEFINE_string(
    'public_key', '', 'the path to the public key used for verifying', required=False)
# bring your own PKI flag
_ROOT_CERTS = flags.DEFINE_list(
    'root_certs', None,
    'paths to pem encoded certifcate files or single file containing used as the root of trust',
    required=False
)


def __check_sigstore_flags():
    if _ID.value == '' or _ID_PROVIDER.value == '':
        log.error('--id_provider and --id are required for sigstore verification')
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
        verifier = verifying.SigstoreVerifier(
            _ID_PROVIDER.value, _ID.value)
    elif _METHOD.value == 'private-key':
        __check_private_key_flags()
        verifier = verifying.KeyVerifier.from_path(_KEY_PATH.value)
    elif _METHOD.value == 'pki':
        __check_pki_flags()
        verifier = verifying.PKIVerifier(_ROOT_CERTS.value)
    elif _METHOD.value == 'skip':
        verifier = verifying.FakeVerifier()
    else:
        raise ValueError(f'unsupported signing method {_METHOD.value}')
    
    log.info(f'Verifying model signature from {_PATH.value}')
    result = model.verify_model(_SIG.value, _PATH.value, verifier)
    log.info(f'Verification result: Passed: {result.passed}\t;\tAdditional information: {result.information}')

if __name__=='__main__':
    app.run(main)