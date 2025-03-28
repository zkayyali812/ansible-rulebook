#  Copyright 2023 Red Hat, Inc.
#
#  Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
#  You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
#  Unless required by applicable law or agreed to in writing, software
#  distributed under the License is distributed on an "AS IS" BASIS,
#  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
#  See the License for the specific language governing permissions and
#  limitations under the License.
import pytest

from ansible_rulebook.exception import InvalidFilterNameException
from ansible_rulebook.util import (
    MASKED_VARIABLE,
    has_builtin_filter,
    mask_sensitive_variable_values,
)


def test_bad_builtin_filter():
    with pytest.raises(InvalidFilterNameException):
        has_builtin_filter("eda.builtin.")


def test_has_builtin_filter():
    assert has_builtin_filter("eda.builtin.insert_meta_info")


def test_has_builtin_filter_missing():
    assert not has_builtin_filter("eda.builtin.something_missing")


def test_builtin_filter_bad_prefix():
    assert not has_builtin_filter("eda.gobbledygook.")


@pytest.mark.parametrize(
    "extra_vars, expected",
    [
        ({"password": "dummy"}, {"password": MASKED_VARIABLE}),
        (
            {
                "TOWER_HOST": "https://ansible.com",
                "TOWER_OAUTH_TOKEN": "dummy-token",
                "TOWER_USERNAME": "admin",
                "TOWER_PASSWORD": "dummy-password",
                "CONTROLLER_HOST": "https://ansible.com",
                "CONTROLLER_OAUTH_TOKEN": "dummy-token",
                "CONTROLLER_USERNAME": "admin",
                "CONTROLLER_PASSWORD": "dummy-password",
            },
            {
                "TOWER_HOST": "https://ansible.com",
                "TOWER_OAUTH_TOKEN": MASKED_VARIABLE,
                "TOWER_USERNAME": "admin",
                "TOWER_PASSWORD": MASKED_VARIABLE,
                "CONTROLLER_HOST": "https://ansible.com",
                "CONTROLLER_OAUTH_TOKEN": MASKED_VARIABLE,
                "CONTROLLER_USERNAME": "admin",
                "CONTROLLER_PASSWORD": MASKED_VARIABLE,
            },
        ),
        (
            {
                "AAP_HOST": "https://ansible.com",
                "AAP_OAUTH_TOKEN": "dummy-token",
                "AAP_USERNAME": "admin",
                "AAP_PASSWORD": "dummy-password",
            },
            {
                "AAP_HOST": "https://ansible.com",
                "AAP_OAUTH_TOKEN": MASKED_VARIABLE,
                "AAP_USERNAME": "admin",
                "AAP_PASSWORD": MASKED_VARIABLE,
            },
        ),
        (
            {
                "postgres_db_host": "https://ansible.com",
                "postgres_db_name": "dummy",
                "postgres_db_port": 5432,
                "postgres_db_password": "dummy-password",
                "postgres_db_user": "dummy",
            },
            {
                "postgres_db_host": "https://ansible.com",
                "postgres_db_name": "dummy",
                "postgres_db_port": 5432,
                "postgres_db_password": MASKED_VARIABLE,
                "postgres_db_user": "dummy",
            },
        ),
        (
            {
                "postgres": {
                    "auth": {"username": "admin", "password": "dummy"}
                },
                "contoller": {
                    "controller_username": "admin",
                    "controller_password": "dummy",
                },
                "test": [
                    {
                        "service1_username": "admin",
                        "service1_password": "dummy",
                        "service1_token": "dummy",
                    },
                    {"service2_username": "admin", "service2_token": "dummy"},
                ],
                "aap_token": "dummy",
            },
            {
                "postgres": {
                    "auth": {"username": "admin", "password": MASKED_VARIABLE}
                },
                "contoller": {
                    "controller_username": "admin",
                    "controller_password": MASKED_VARIABLE,
                },
                "test": [
                    {
                        "service1_username": "admin",
                        "service1_password": MASKED_VARIABLE,
                        "service1_token": MASKED_VARIABLE,
                    },
                    {
                        "service2_username": "admin",
                        "service2_token": MASKED_VARIABLE,
                    },
                ],
                "aap_token": MASKED_VARIABLE,
            },
        ),
    ],
)
def test_mask_sensitive_variable_values(extra_vars, expected):
    assert mask_sensitive_variable_values(extra_vars) == expected
