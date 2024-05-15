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
"""Script to sign models."""

import os

from absl import app
from absl import logging as log
from absl import flags

import model

from signature import signing


_PATH = flags.DEFINE_string('model_path', '', 'the path to the model\'s base folder.')
_METHOD = flags.DEFINE_enum(
    'method', None, model.SUPPORTED_METHODS, 'the signing method to use.'
)
_SIG_OUT = flags.DEFINE_string(
    'out', '', 'the output file, it defaults to model_path/signature.json', required=False
)

# private key option
_KEY_PATH = flags.DEFINE_string(
    'private_key', '', 'the path to the private key PEM file', required=False
)

# PKI options
_CERT_CHAIN_PATH = flags.DEFINE_list(
    'cert_chain', None, 
    'paths to pem encoded certifcate files or single file containing the chain', required=False
)
_SIGNING_CERT_PATH = flags.DEFINE_string(
     'signing_cert', '', 'the pem encoded signing cert', required=False
)


def __check_private_key_options():
    if _KEY_PATH.value == '':
            log.error(
                '--private_key must be set to a valid private key PEM file'
            )
            exit()


def __check_pki_options():
    __check_private_key_options()
    if _SIGNING_CERT_PATH.value == '':
        log.error(
            '--signing_cert must be set to a valid PEM encoded signing certificate'
        )
        exit()
    if _CERT_CHAIN_PATH.value == '':
        log.warning('No certificate chain provided')


def main(_):
    signer: signing.Signer
    log.info(f'Creating signer for {_METHOD.value}')
    if _METHOD.value == 'sigstore':
        signer = signing.SigstoreSigner()
    elif _METHOD.value == 'private-key':
        __check_private_key_options()
        signer = signing.KeySigner(_KEY_PATH.value)
    elif _METHOD.value == 'pki':
        __check_pki_options()
        signer = signing.PKISigner(
            _KEY_PATH.value, _SIGNING_CERT_PATH.value, _CERT_CHAIN_PATH.value)
    elif _METHOD.value == 'skip':
        signer = signing.FakeSigner()
    else:
        raise ValueError(f'unsupported signing method {_METHOD.value}')

    log.info(f'Signing model at {_PATH.value}')
    bundle = model.sign_model(_PATH.value, signer)
    sig_path = os.path.join(_PATH.value, 'signature.json') if _SIG_OUT.value == '' else _SIG_OUT.value
    log.info(f'Storing signature at "{sig_path}"')
    model.store_bundle(bundle, sig_path)


if __name__ == '__main__':
    app.run(main)
