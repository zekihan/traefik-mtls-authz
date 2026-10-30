#!/usr/bin/env python3
"""Parse every fenced YAML block in the docs and check traefik-mtls-authz policy examples.

Usage: python3 scripts/check_docs_yaml.py [file ...]   (default: README.md docs/*.md)
Exit status is non-zero when any block fails to parse or a policy example is malformed.
"""

import glob
import json
import re
import sys

import yaml

PLUGIN_KEY = "traefik-mtls-authz"
PREFIX = re.compile(r"^urn:noqer:mtls:[a-z0-9]+(?:-[a-z0-9]+)*:$")
FORWARD_HEADER = re.compile(r"^X-Mtls-[!#$%&'*+\-.^_`|~0-9A-Za-z]+$", re.IGNORECASE)
HEX64 = re.compile(r"^[0-9a-f]{64}$")
POLICY_KEYS = {
    "schemaVersion",
    "app",
    "policyRevision",
    "trustedIssuers",
    "identityPrefix",
    "identities",
    "disabledIdentities",
    "blockedFingerprints",
    "constraints",
    "stripHeaders",
    "forwardIdentityHeader",
}
FENCE = re.compile(r"^```yaml[^\n]*\n(.*?)^```", re.MULTILINE | re.DOTALL)


def find_plugin_blocks(node):
    """Yield every mapping stored under a traefik-mtls-authz key, at any depth."""
    if isinstance(node, dict):
        for key, value in node.items():
            if key == PLUGIN_KEY:
                yield value
            else:
                yield from find_plugin_blocks(value)
    elif isinstance(node, list):
        for item in node:
            yield from find_plugin_blocks(item)


def unique_json_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key {key!r}")
        result[key] = value
    return result


def check_policy(block, where):
    errors = []
    if not isinstance(block, dict) or set(block) not in ({"policy"}, {"policyJSON"}):
        return [f"{where}: plugin block must contain exactly one key 'policy' or 'policyJSON'"]
    if "policyJSON" in block:
        try:
            policy = json.loads(block["policyJSON"], object_pairs_hook=unique_json_object)
        except (ValueError, TypeError) as exc:
            return [f"{where}: invalid policyJSON: {exc}"]
    else:
        policy = block["policy"]
    if not isinstance(policy, dict):
        return [f"{where}: policy must be a mapping, got {type(policy).__name__}"]
    unknown = set(policy) - POLICY_KEYS
    if unknown:
        errors.append(f"{where}: unknown policy keys {sorted(unknown)}")
    version = policy.get("schemaVersion")
    if type(version) is not int or version != 1:  # bool is an int subclass; True == 1 must fail
        errors.append(f"{where}: schemaVersion must be the integer 1")
    prefix = policy.get("identityPrefix")
    if not isinstance(prefix, str) or not PREFIX.fullmatch(prefix) or len(prefix) >= 128:
        errors.append(f"{where}: identityPrefix must be a full profile namespace ending with ':'")
        prefix = ""
    issuers = policy.get("trustedIssuers")
    if not isinstance(issuers, list) or not issuers or not all(
        isinstance(x, str) and HEX64.match(x) for x in issuers
    ):
        errors.append(f"{where}: trustedIssuers must be a non-empty list of 64 lowercase hex strings")
    for key in ("identities", "disabledIdentities"):
        values = policy.get(key, [])
        if not isinstance(values, list) or not all(isinstance(x, str) and x.startswith(prefix) for x in values):
            errors.append(f"{where}: {key} must be a list of strings starting with the identityPrefix")
    constraints = policy.get("constraints", {})
    if not isinstance(constraints, dict):
        errors.append(f"{where}: constraints must be a mapping")
    else:
        for identity, rule in constraints.items():
            enrolled = policy.get("identities", [])
            if isinstance(enrolled, list) and identity not in enrolled:
                errors.append(f"{where}: constraint key {identity!r} must be enrolled")
            if not identity.startswith(prefix):
                errors.append(f"{where}: constraint key {identity!r} is outside the identityPrefix")
            if not isinstance(rule, dict) or not rule.get("methods") or not rule.get("paths"):
                errors.append(f"{where}: constraint {identity!r} needs non-empty methods and paths")
    forward = policy.get("forwardIdentityHeader", "")
    if not isinstance(forward, str) or (forward and not FORWARD_HEADER.fullmatch(forward)):
        errors.append(f"{where}: forwardIdentityHeader must be empty or a valid X-Mtls-* token")
    if policy.get("stripHeaders", True) is not True:
        errors.append(f"{where}: stripHeaders must be true or omitted")
    if not isinstance(policy.get("app"), str) or not policy["app"].strip():
        errors.append(f"{where}: app must be a non-empty string")
    for entry in policy.get("blockedFingerprints", []):
        if not isinstance(entry, dict) or not HEX64.match(str(entry.get("fingerprint", ""))):
            errors.append(f"{where}: blockedFingerprints entries need a 64 lowercase hex fingerprint")
    return errors


def check_file(path):
    text = open(path, encoding="utf-8").read()
    errors = []
    blocks = 0
    if path.endswith(".traefik.yml"):
        try:
            metadata = yaml.safe_load(text)
            return 1, check_policy(metadata.get("testData"), f"{path}:testData")
        except yaml.YAMLError as exc:
            return 1, [f"{path}: YAML parse error: {exc}"]
    for match in FENCE.finditer(text):
        blocks += 1
        line = text.count("\n", 0, match.start()) + 1
        where = f"{path}:{line}"
        try:
            documents = list(yaml.safe_load_all(match.group(1)))
        except yaml.YAMLError as exc:
            errors.append(f"{where}: YAML parse error: {exc}")
            continue
        for document in documents:
            for block in find_plugin_blocks(document):
                errors.extend(check_policy(block, where))
    return blocks, errors


def main(argv):
    paths = argv[1:] or ["README.md", *sorted(glob.glob("docs/*.md")), ".traefik.yml"]
    total = 0
    failures = []
    for path in paths:
        blocks, errors = check_file(path)
        total += blocks
        failures.extend(errors)
    for failure in failures:
        print(failure, file=sys.stderr)
    print(f"checked {total} yaml block(s) in {len(paths)} file(s); {len(failures)} problem(s)")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
