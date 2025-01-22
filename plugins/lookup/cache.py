#!/usr/bin/env python3
# coding: utf-8
# pyright: reportMissingImports=false
# pyright: reportArgumentType=false
# pylint: disable=import-error
# pylint: disable=no-member
# pylint: disable=ungrouped-imports
# pylint: disable=too-few-public-methods

"""
Source: https://github.com/GoodRx/ansible-cached-lookup/pull/5

An Ansible lookup plugin that caches the results of any other lookup.

By default, Ansible evaluates any lookups in a group/host var whenever the var
is accessed. For example, given a group/host var:

.. code-block:: yaml

    content: "{{ lookup('pipe', 'command') }}"

Any tasks that access ``content`` (e.g. in a template) will re-evaluate
the lookup, which adds up very quickly.

.. seealso:: :attr:`.DOCUMENTATION`, :attr:`.EXAMPLES`, `ansible/ansible#9623
    <https://github.com/ansible/ansible/issues/9623>`_
"""

from __future__ import absolute_import, division, print_function

import hashlib
import json
import os.path

from ansible import constants as C
from ansible.errors import AnsibleError
from ansible.plugins.loader import lookup_loader
from ansible.plugins.lookup import LookupBase

__version__ = "1.0.0"


DOCUMENTATION = """
lookup: cache
short_description: Cache the result of a lookup
description:
  - Run a lookup and cache the result for the duration of the play. This is
    most useful for lookups, which are typically re-evaluated every time they are used
options:
  Terms:
    description: The lookup and any arguments to perform.
    required: True
notes:
  - Results are cached in C(DEFAULT_LOCAL_TMP) and will be deleted at the end of
    the play.
"""

EXAMPLES = """
var: "{{ lookup('bigouden.utils.cache', 'pipe', 'command') }}"
"""

try:
    from __main__ import display
except ImportError:
    from ansible.utils.display import Display

    display = Display()

CACHE_FILE_PATH = os.path.join(C.DEFAULT_LOCAL_TMP, "cache_lookup")

try:
    if os.path.exists(CACHE_FILE_PATH):
        with open(CACHE_FILE_PATH, "r", encoding="utf-8") as CACHE_FILE:
            CACHE = json.load(CACHE_FILE)
    else:
        CACHE = {}
except (IOError, ValueError):
    CACHE = {}


def gen_hash(key):
    """Generate Hash"""
    sha256_hash = hashlib.sha256()
    string_key = str(key).encode("utf-8")
    sha256_hash.update(string_key)
    return sha256_hash.hexdigest()


class LookupModule(LookupBase):
    """Lookup Module Class"""

    def run(self, terms, variables=None, **kwargs):
        """Run"""

        lookup_name, terms = terms[0], terms[1:]
        sorted_kwargs = {key: kwargs[key] for key in sorted(kwargs)}
        key = gen_hash(f"{terms[0]}{sorted_kwargs}")

        try:
            result = CACHE[key]
            display.verbose(f"'cache' lookup cache hit for {key}")
        except KeyError as exception:
            lookup = lookup_loader.get(
                lookup_name, loader=self._loader, templar=self._templar
            )
            if lookup is None:
                raise AnsibleError(
                    f"lookup plugin ({lookup_name}) not found"
                ) from exception

            result = lookup.run(terms, variables=variables, **kwargs)
            CACHE[key] = result

            with open(CACHE_FILE_PATH, "w", encoding="utf-8") as cache_file:
                json.dump(CACHE, cache_file)

            display.verbose(f"'cache' lookup cache miss for {key}")

        return result
