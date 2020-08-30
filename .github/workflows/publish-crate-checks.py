from subprocess import check_output, CalledProcessError
import re
import os
import datetime
import json


def fail(msg):
    print(f'::error::{msg}')
    raise SystemExit(1)


cargo_toml = open('Cargo.toml').read()
version = re.search(r'(?m:^version = "(.*?)"$)', cargo_toml)
if not version:
    fail("Could not parse version")
version = version[1]

print(f"::set-output name=version::{version}")


def get_rev(rev):
    try:
        cmd = ['git', 'rev-parse', rev]
        rev_hash = check_output(cmd, text=True).strip()
    except CalledProcessError:
        fail(f"No git revision {rev} found")
    return rev_hash


def fetch_rev(rev):
    try:
        cmd = ['git', 'fetch', 'origin', f'{rev}:{rev}']
        check_output(cmd, text=True)
    except CalledProcessError:
        fail(f"Could not fetch revision {rev}")
    return get_rev(rev)


if get_rev('HEAD') != fetch_rev(f'refs/tags/v{version}'):
    fail(f"Tag v{version} does not point at current HEAD")

try:
    status = check_output(['hub', 'ci-status', '-f', '%t: %S%n'], text=True)
except CalledProcessError:
    status = ''

if 'bors: success' not in status:
    fail(f"Commit not successfully checked by bors")

display_name = os.environ['project_display_name']

changelog = open('CHANGELOG.md').read()

date = datetime.date.today().isoformat()

header_string = f'{display_name} {version} ({date})'

entry_re = r'\n## ' + re.escape(header_string) + r'\n+(.*?)\n\n*(## |$)'

entry = re.search(entry_re, changelog, re.DOTALL)
if not entry:
    fail(f"Did not find changelog entry for {header_string}")

entry = entry[1]

print(f"::set-output name=changelog::{json.dumps(entry)}")
