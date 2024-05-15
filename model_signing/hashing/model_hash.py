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
"""This package provides functionality to hash the model folder and create a statement."""
from typing import Optional

import hashlib
import os
import pathlib

from concurrent import futures

from in_toto_attestation.v1 import statement 
from in_toto_attestation.v1 import resource_descriptor as res_desc


_CHUNK_SIZE = int(1_000_000_000) # ~1GB
_MAX_WORKERS = 10


def __hash_file(path: pathlib.Path) -> bytes:
    h = hashlib.sha256()
    with open(path, 'rb') as fd:
        while True:
            data = fd.read(_CHUNK_SIZE)
            if not data:
                break
            h.update(data)
    return h.hexdigest()


def __create_subject(full_path: pathlib.Path, internal_path: str) -> res_desc.ResourceDescriptor:
    return res_desc.ResourceDescriptor(
        # TODO: clean path; make sure to only store parts that are in the model folder.
        # e.g. instead of /a/b/c/model_base/weights/chunk1-1000.gz only store weights/chunk1-100.gz
        name=internal_path,
        digest={'sha256': __hash_file(full_path)}
    )


def hash_model(
        path: str,
        ignore: Optional[list[str]] = ['signature.json'],
        model_metadata: dict[str, str]={'name': 'unknown'}) -> statement.Statement:
    """Hashes the model and returns an in-toto attestation Statement.

    Args:
        path (str): path to the model's base folder
        ignore (Optional[list[str]], optional): filenames to be ignored. Defaults to ['signature.json'].
        model_metadata (_type_, optional): metadata about the model. Defaults to {'name': 'unknown'}.

    Raises:
        ValueError: if the model does not exist
        ValueError: if the input path is not a directory

    Returns:
        statement.Statement: containing the file hashes of the model and the provided metadata.
    """
    subjects = []
    if not os.path.exists(path):
        raise ValueError(f'path "{path}" does not exist')
    if not os.path.isdir(path):
        raise ValueError('hash_model expects a directory as input')
    filepaths = []
    for dir_path, _, file_names in os.walk(path):
        for f_name in file_names:
            if f_name in ignore:
                continue
            full_path = os.path.join(dir_path, f_name)
            filepaths.append(
                (full_path, full_path.replace(path, ''))
            )
    with futures.ThreadPoolExecutor(max_workers=_MAX_WORKERS) as executor:
        future_to_subject = [executor.submit(
            __create_subject, full_path, internal_path) for full_path, internal_path in filepaths]
        for f in futures.as_completed(future_to_subject):
            subjects.append(f.result().pb)
    return statement.Statement(
        subjects=subjects,
        predicate_type='model_signing/v1',
        predicate=model_metadata,
    )
