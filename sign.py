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
"""Script to sign models."""
import argparse
import os
import pathlib

from absl import app
from absl import logging as log
from absl import flags

from model_signing import model
from model_signing.hashing import file
from model_signing.hashing import memory
from model_signing.serialization import serialize_by_file
from model_signing.signature import SUPPORTED_METHODS
from model_signing.signature import key
from model_signing.signature import pki
from model_signing.signature import signing
from model_signing.signature import sigstore
from model_signing.signature import fake

# _PATH = flags.DEFINE_string(
#     'model_path', '', 'the path to the model\'s base folder.')
# _METHOD = flags.DEFINE_enum(
#     'method', None, SUPPORTED_METHODS, 'the signing method to use.'
# )
# _SIG_OUT = flags.DEFINE_string(
#     'out',
#     '',
#     'the output file, it defaults to model_path/signature.json',
#     required=False)

# # private key option
# _KEY_PATH = flags.DEFINE_string(
#     'private_key', '', 'the path to the private key PEM file', required=False
# )

# # PKI options
# _CERT_CHAIN_PATH = flags.DEFINE_list(
#     'cert_chain',
#     None,
#     ('paths to pem encoded certifcate files or',
#      ' single file containing the chain'),
#     required=False)
# _SIGNING_CERT_PATH = flags.DEFINE_string(
#      'signing_cert', '', 'the pem encoded signing cert', required=False
# )


def __arguments() -> argparse.Namespace:
    parser = argparse.ArgumentParser('Script to sign models')
    parser.add_argument(
        '--model_path',
        help='path to the model to sign',
        required=True,
        type=pathlib.Path,
        dest='model_path')
    parser.add_argument(
        '--sig_out',
        help='the output file, it defaults to model_path/signature.json',
        required=False,
        type=str,
        dest='sig_out')

    method_cmd = parser.add_subparsers(required=True, dest='method')
    # Sigstore
    method_cmd.add_parser('sigstore')
    # PKI
    pki = method_cmd.add_parser('pki')
    pki.add_argument(
        '--cert_chain',
        help='paths to pem encoded certificate files or a single file containing a chain',
        required=False,
        type=list[str],
        default=[],
        nargs='+',
        dest='cert_chain_path')
    pki.add_argument(
        '--signing_cert',
        help='the pem encoded signing cert',
        required=True,
        type=pathlib.Path,
        dest='signing_cert_path')
    # private key
    pKey = method_cmd.add_parser('private-key')
    pKey.add_argument(
        '--private_key',
        help='the path to the private key PEM file',
        required=True,
        type=pathlib.Path,
        dest='key_path')
    # skip
    method_cmd.add_parser('skip')

    return parser.parse_args()


def __get_payload_signer(args: argparse.Namespace) -> signing.Signer:
    if _METHOD.value == 'sigstore':
        return sigstore.SigstoreSigner()
    elif _METHOD.value == 'private-key':
        __check_private_key_options()
        return key.ECKeySigner.from_path(_KEY_PATH.value)
    elif _METHOD.value == 'pki':
        __check_pki_options()
        return pki.PKISigner.from_path(
            _KEY_PATH.value, _SIGNING_CERT_PATH.value, _CERT_CHAIN_PATH.value)
    elif _METHOD.value == 'skip':
        return fake.FakeSigner()
    else:
        raise ValueError(f'unsupported signing method {_METHOD.value}')


def __check_private_key_options(args: argparse.Namespace):
    if _KEY_PATH.value == '':
        log.error(
            '--private_key must be set to a valid private key PEM file'
        )
        exit()


def __check_pki_options(args: argparse.Namespace):
    __check_private_key_options()
    if _SIGNING_CERT_PATH.value == '':
        log.error(
            ('--signing_cert must be set to a valid ',
             'PEM encoded signing certificate')
        )
        exit()
    if _CERT_CHAIN_PATH.value == '':
        log.warning('No certificate chain provided')


def main(_):
    args = __arguments()
    print(args)
    quit()
    log.info(f'Creating signer for {_METHOD.value}')
    payload_signer = __get_payload_signer()
    log.info(f'Signing model at {_PATH.value}')
    sig_path_name = os.path.join(
        _PATH.value, 'signature.json') \
        if _SIG_OUT.value == '' else _SIG_OUT.value
    sig_path = pathlib.Path(sig_path_name)

    def hasher_factory(file_path: pathlib.Path) -> file.FileHasher:
        return file.SimpleFileHasher(
            file=file_path,
            content_hasher=memory.SHA256())

    serializer = serialize_by_file.FilesSerializer(
        file_hasher_factory=hasher_factory)

    bundle = model.sign(
        model_path=pathlib.Path(_PATH.value),
        signer=payload_signer,
        serializer=serializer,
        ignore_paths=[sig_path.name]
    )

    log.info(f'Storing signature at "{sig_path_name}"')
    sig_path.write_text(bundle.to_json())


if __name__ == '__main__':
    app.run(main)
