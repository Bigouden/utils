#!/usr/bin/env python3
# coding: utf-8
# pyright: reportMissingImports=false
# pyright: reportArgumentType=false
# pylint: disable=import-error
# pylint: disable=no-member
# pylint: disable=ungrouped-imports
# pylint: disable=too-few-public-methods
# pylint: disable=import-self
# pylint: disable=broad-exception-raised
# pylint: disable=attribute-defined-outside-init
# mypy: disable-error-code="attr-defined"

"""
Source: https://github.com/passbolt/lab-passbolt-ansible-collection

An Ansible lookup plugin that retrieve resources and secrets from passbolt API.
"""

from __future__ import absolute_import, division, print_function

import json
import secrets
import string
from os import environ

from ansible.plugins.lookup import LookupBase
from ansible.utils.display import Display
from passbolt import PassboltAPI

__version__ = "1.0.0"


DOCUMENTATION = """
lookup: passbolt
short_description: Cache the result of a lookup
description:
  - This lookup returns resources and secrets from passbolt API.
options:
  per_uuid:
    description: The searched term is a passbolt resource UUID
    type: bool
    required: False
    default: False
  username:
    description: filter the searched term per username
    type: str
    require: False
    default: ""
  uri:
    description: filter the searched term per uri
    type: str
    require: False
    default: ""
  description:
    description: filter the searched term per description
    type: str
    require: False
    default: ""
"""

EXAMPLES = """
- name: "Passbolt lookup plugin / fetch one"
  debug:
    var: lookup('passbolt', 'OVH')
- name: "Passbolt lookup plugin / loop with filters"
  debug:
    var: item
  loop:
    - "{{ lookup('bigouden.utils.passbolt', 'gitlab') }}"
    - "{{ lookup('bigouden.utils.passbolt', 'a294b8d6-5dae-6-9e49', per_uuid='true') }}"
    - "{{ lookup('bigouden.utils.passbolt', 'OVH', username='zero@ellingson.corp') }}"

- name: "Passbolt lookup plugin / fetch list of items"
  debug:
    var: item
  with_passbolt:
    - "n8n"
    - "Scaleway"
    - "This doesn't exists"
- name: Generate AWS credentials profile
  ansible.builtin.copy:
    vars:
      aws:
        access_key: "{{ lookup('bigouden.utils.passbolt', 'AWS').password }}"
        secret_key: "{{ lookup('bigouden.utils.passbolt', 'AWS').description }}"
    dest: ${HOME}/.aws/credentials
    owner: "{{ lookup('env', 'USER') }}"
    mode: "0600"
    content: |
      [default]
      aws_access_key_id={{ aws.access_key }}
      aws_secret_access_key={{ aws.secret_key }}
"""

RETURN = """
  _raw:
    description:
      - content of file(s)
    type: list
    elements: str
"""

display = Display()


class LookupModule(LookupBase):
    """Lookup Module Class"""

    def _get_value(
        self, selected_variable, variables, environment_variables, default=str()
    ):
        variable = variables.get(selected_variable, None)
        if variable is None:
            return self._get_env_value(
                selected_variable=selected_variable,
                environment_variables=environment_variables,
                default=default,
            )
        return variable

    def _get_env_value(self, selected_variable, environment_variables, default=str()):
        os_environ_variable = environ.get(selected_variable, None)
        if os_environ_variable is not None:
            default = os_environ_variable

        return self._templar.template(
            next(
                (
                    item.get(selected_variable)
                    for item in environment_variables
                    if item.get(selected_variable)
                ),
                default,
            )
        )

    def _search(self, item, kwargs):
        res = 0
        expected = len(kwargs)

        for k in kwargs:
            if kwargs[k] == item[k]:
                res += 1

        return expected == res

    def _create_new_password(self):
        characters = string.ascii_letters + string.digits
        if (
            str(self.dict_config.get("new_resource_password_special_chars")).lower()
            == "true"
        ):
            characters += string.punctuation
        return "".join(
            secrets.choice(characters)
            for i in range(int(self.dict_config.get("new_resource_password_length")))
        )

    def _create_new_resource(self, kwargs):
        new_password = kwargs.get("password", self._create_new_password())
        new_description = kwargs.get("description", "Ansible Generated")
        new_resource = {
            "name": kwargs.get("name"),
            "username": kwargs.get("username"),
            "uri": kwargs.get("uri"),
            "resource_type_id": self.p.resource_types["password-and-description"],
            "folder_parent_id": kwargs.get("folder_parent_id"),
            "secrets": [
                {
                    "data": self.p.encrypt(
                        {"description": new_description, "password": new_password},
                        self.p.get_user_public_key(self.p.user_id),
                    )
                }
            ],
        }

        r = self.p.create_resource(new_resource)
        if r.status_code == 200:
            resource = json.loads(r.text).get("body")
            resource_secrets = {
                "password": new_password,
                "description": new_description,
            }
            return self._format_result(resource, resource_secrets)
        return self._format_result({}, {})

    def _format_result(self, resource, resource_secrets):
        return {
            "name": resource.get("name", ""),
            "uri": resource.get("uri", ""),
            "username": resource.get("username", ""),
            "password": resource_secrets.get("password", ""),
            "description": (
                "description" in resource_secrets
                and resource_secrets.get("description", "")
                or resource.get("description", "")
            ),
            "deleted": resource.get("deleted", ""),
            "created": resource.get("created", ""),
            "modified": resource.get("modified", ""),
            "modified_by": resource.get("modified_by", ""),
            "resource_type_id": resource.get("resource_type_id", ""),
            "folder_parent_id": resource.get("folder_parent_id", ""),
            "personal": resource.get("personal", ""),
        }

    def _get_config(self, variables):
        return {
            "base_url": self._get_value(
                "PASSBOLT_BASE_URL", variables, variables.get("environment")
            ),
            "private_key": self._get_value(
                "PASSBOLT_PRIVATE_KEY", variables, variables.get("environment")
            ),
            "passphrase": self._get_value(
                "PASSBOLT_PASSPHRASE", variables, variables.get("environment")
            ),
            "gpg_binary": self._get_value(
                "PASSBOLT_GPG_BINARY",
                variables,
                variables.get("environment"),
                default="gpg",
            ),
            "gpg_library": self._get_value(
                "PASSBOLT_GPG_LIBRARY",
                variables,
                variables.get("environment"),
                default="PGPy",
            ),
            "fingerprint": self._get_value(
                "PASSBOLT_FINGERPRINT", variables, variables.get("environment")
            ),
            "verify": self._get_value(
                "PASSBOLT_VERIFY", variables, variables.get("environment"), default=True
            ),
            "timeout": self._get_value(
                "PASSBOLT_TIMEOUT", variables, variables.get("environment")
            ),
            "create_new_resource": self._get_value(
                "PASSBOLT_CREATE_NEW_RESOURCE",
                variables,
                variables.get("environment"),
                default=False,
            ),
            "new_resource_password_length": self._get_value(
                "PASSBOLT_NEW_RESOURCE_PASSWORD_LENGTH",
                variables,
                variables.get("environment"),
                default=20,
            ),
            "new_resource_password_special_chars": self._get_value(
                "PASSBOLT_NEW_RESOURCE_PASSWORD_SPECIAL_CHARS",
                variables,
                variables.get("environment"),
                default=False,
            ),
        }

    def passbolt_init(self, variables, kwargs):
        """Passbolt Init"""

        self.dict_config = self._get_config(variables)
        self.p = PassboltAPI(dict_config=self.dict_config)

        if kwargs.get("per_uuid") != "true":
            self.passbolt_resources = self.p.get_resources()

    def get_resource_per_uuid(self, uuid):
        """Get Resource Per UUID"""

        resource = self.p.get_resource_per_uuid(uuid)
        if not resource:
            resource = {}
        return resource

    def get_resource_per_term(self, term):
        """Get Resource Per Term"""

        resource = next(
            (item for item in self.passbolt_resources if item.get("name") == term),
            {},
        )
        return resource

    def get_resource_per_kwargs(self, kwargs):
        """Get Resource Per Kwargs"""

        resource = next(
            (item for item in self.passbolt_resources if self._search(item, kwargs)),
            {},
        )
        return resource

    def run(self, terms, variables=None, **kwargs):
        """Run"""

        ret = []

        self.set_options(var_options=variables, direct=kwargs)

        self.passbolt_init(variables, kwargs)
        # removing description and password for the search
        description = kwargs.pop("description", None)
        password = kwargs.pop("password", None)
        for term in terms:
            display.debug(f"Passbolt lookup term: {term}")
            kwargs["name"] = uuid = term

            if kwargs.get("per_uuid") == "true":
                resource = self.get_resource_per_uuid(uuid)
            elif kwargs.get("wantlist"):  # with_passbolt case
                resource = self.get_resource_per_term(term)
            elif len(kwargs):  # search for term plus username, uri, etc.
                resource = self.get_resource_per_kwargs(kwargs)
            else:
                resource = self.get_resource_per_term(term)
            if resource.get("id"):
                # We got a resource, fetch their secrets
                resource_secret_decrypted = self.p.decrypt(
                    self.p.get_resource_secret(resource.get("id"))
                )
                try:
                    resource_secrets = (
                        self.dict_config.get("gpg_library", "PGPy") == "gnupg"
                        and json.loads(resource_secret_decrypted.data)
                        or json.loads(resource_secret_decrypted)
                    )
                except json.decoder.JSONDecodeError:
                    # Only password is returned when description field is not encrypted
                    resource_secrets = (
                        {"password": resource_secret_decrypted.data}
                        if self.dict_config.get("gpg_library", "PGPy") == "gnupg"
                        else {"password": resource_secret_decrypted}
                    )
                ret.append(self._format_result(resource, resource_secrets))
            else:
                if str(self.dict_config.get("create_new_resource")).lower() == "true":
                    # if r
                    if description:
                        kwargs["description"] = description
                    if password:
                        kwargs["password"] = password
                    ret.append(self._create_new_resource(kwargs))
                else:
                    raise Exception(f"resource {terms[0]} not found")

        return ret
