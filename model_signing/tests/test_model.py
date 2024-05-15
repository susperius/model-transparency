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
import pytest

from in_toto_attestation.v1 import statement
from in_toto_attestation.v1 import resource_descriptor as res_desc

import model

def test_compare_subjects_success():
    stmnt_a = statement.Statement(
        subjects=[
            res_desc.ResourceDescriptor(name='abc', digest={'sha256': b'12345'}).pb,
            res_desc.ResourceDescriptor(name='def', digest={'sha256': b'67890'}).pb,
            res_desc.ResourceDescriptor(name='ghi', digest={'sha256': b'11111'}).pb,
        ],
        predicate_type='model_signing/v1',
        predicate={'name': 'unknown'},
    )
    stmnt_b = statement.Statement(
        subjects=[
            res_desc.ResourceDescriptor(name='abc', digest={'sha256': b'12345'}).pb,
            res_desc.ResourceDescriptor(name='def', digest={'sha256': b'67890'}).pb,
            res_desc.ResourceDescriptor(name='ghi', digest={'sha256': b'11111'}).pb,
        ],
        predicate_type='model_signing/v1',
        predicate={'name': 'unknown'},
    )

    result = model.__compare_subjects(stmnt_a.pb, stmnt_b.pb)

    assert result[0] == True


def test_compare_subjects_length_failure():
    stmnt_a = statement.Statement(
        subjects=[
            res_desc.ResourceDescriptor(name='abc', digest={'sha256': b'12345'}).pb,
            res_desc.ResourceDescriptor(name='def', digest={'sha256': b'67890'}).pb,
            res_desc.ResourceDescriptor(name='ghi', digest={'sha256': b'11111'}).pb,
        ],
        predicate_type='model_signing/v1',
        predicate={'name': 'unknown'},
    )
    stmnt_b = statement.Statement(
        subjects=[
            res_desc.ResourceDescriptor(name='abc', digest={'sha256': b'12345'}).pb,
            res_desc.ResourceDescriptor(name='def', digest={'sha256': b'67890'}).pb,
        ],
        predicate_type='model_signing/v1',
        predicate={'name': 'unknown'},
    )

    result = model.__compare_subjects(stmnt_a.pb, stmnt_b.pb)

    assert result[0] == False


def test_compare_subjects_length_failure():
    stmnt_a = statement.Statement(
        subjects=[
            res_desc.ResourceDescriptor(name='abc', digest={'sha256': b'12345'}).pb,
            res_desc.ResourceDescriptor(name='def', digest={'sha256': b'67890'}).pb,
            res_desc.ResourceDescriptor(name='ghi', digest={'sha256': b'11111'}).pb,
        ],
        predicate_type='model_signing/v1',
        predicate={'name': 'unknown'},
    )
    stmnt_b = statement.Statement(
        subjects=[
            res_desc.ResourceDescriptor(name='abc', digest={'sha256': b'12345'}).pb,
            res_desc.ResourceDescriptor(name='def', digest={'sha256': b'67890'}).pb,
            res_desc.ResourceDescriptor(name='ghi', digest={'sha256': b'11112'}).pb,
        ],
        predicate_type='model_signing/v1',
        predicate={'name': 'unknown'},
    )

    result = model.__compare_subjects(stmnt_a.pb, stmnt_b.pb)

    assert result[0] == False

def test_compare_subjects_unsupported_hash_failure():
    stmnt_a = statement.Statement(
        subjects=[
            res_desc.ResourceDescriptor(name='abc', digest={'myfancyhash': b'12345'}).pb,
        ],
        predicate_type='model_signing/v1',
        predicate={'name': 'unknown'},
    )
    stmnt_b = statement.Statement(
        subjects=[
            res_desc.ResourceDescriptor(name='abc', digest={'myfancyhash': b'12345'}).pb,
        ],
        predicate_type='model_signing/v1',
        predicate={'name': 'unknown'},
    )

    result = model.__compare_subjects(stmnt_a.pb, stmnt_b.pb)

    assert result[0] == False