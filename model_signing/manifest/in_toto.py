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
"""
This package provides functionality to convert file based manifests
to in-toto statements. It is necessary because sigstore does not
support arbitrary payloads in DSSE envelopes.
"""
import pathlib

from in_toto_attestation.v1 import statement
from in_toto_attestation.v1 import resource_descriptor

from model_signing.hashing.hashing import Digest
from model_signing.manifest import manifest
from model_signing.manifest.manifest import FileLevelManifest
from model_signing.manifest.manifest import FileManifestItem


_PREDICATE_TYPE = 'model_signing/v1/manifest'
_FILE_LEVEL_MANIFEST = 'FileLevelManifest'


def _file_level_manifest_to_statement(
        manifest: FileLevelManifest,
        ) -> statement.Statement:
    """
    Converts a model signing FileLevelManifest to an
    in-toto statement.

    Args:
        manifest (FileLevelManifest): the manifest to convert
        algorithm (str): the used hash algorithm

    Returns:
        statement.Statement: the in-toto statement representing the manifest
    """
    subjects: list[resource_descriptor.ResourceDescriptor] = []
    for path, digest in manifest.files.items():
        s = resource_descriptor.ResourceDescriptor(
            name=str(path),
            digest={digest.algorithm: digest.digest_hex},
        ).pb
        subjects.append(s)
    return statement.Statement(
        subjects=subjects,
        predicate_type=_PREDICATE_TYPE,
        predicate={'manifest_type': _FILE_LEVEL_MANIFEST},
        )


def _statement_to_file_level_manifest(
        statement: statement.Statement,
        ) -> FileLevelManifest:
    """
    Converts an in-toto statement to a FileLevelManifest.

    Args:
        statement (statement.Statement): the in-toto statement
        algorithm (str): the hash algorithm used

    Returns:
        FileLevelManifest: the resutling FileLevelManifest
    """
    items: list[FileManifestItem] = []
    for s in statement.pb.subject:
        # no support for multiple hashes
        alg, dig = list(s.digest.items())[0]
        items.append(
            FileManifestItem(
                path=pathlib.Path(s.name),
                digest=Digest(
                    algorithm=alg,
                    digest_value=bytes.fromhex(dig),
                )
            )
        )
    return FileLevelManifest(items)


def manifest_to_statement(
        model_manifest: manifest.Manifest
        ) -> statement.Statement:
    """Converts a manifest to an in-toto statement

    Args:
        model_manifest (manifest.Manifest): the manifest

    Raises:
        ValueError: for non supported manifest types

    Returns:
        statement.Statement: the resulting in-toto statement
    """
    # TODO(#248): support for the other manifest types
    if isinstance(model_manifest, manifest.FileLevelManifest):
        return _file_level_manifest_to_statement(model_manifest)
    raise ValueError('manifest type not supported')


def statement_to_manifest(
        stmnt: statement.Statement
        ) -> manifest.Manifest:
    """Converts a statement to a manifest type.

    The type of the manifest depends on the in-tota statments
    `manifest_type` predicate.

    Args:
        stmnt (statement.Statement): the statement

    Raises:
        ValueError: for non supported manifest types

    Returns:
        manifest.Manifest: manifest according to the statement
    """
    # TODO(#248): support for the other manifest types
    if stmnt.pb.predicate['manifest_type'] == _FILE_LEVEL_MANIFEST:
        return _statement_to_file_level_manifest(stmnt)
    raise ValueError('manifest type not supported')
