#!/usr/bin/env python
import argparse
import getpass
import json
import requests
import shutil
import tempfile
from base64 import b64decode
from signing_clients.apps import JarExtractor


class SigningError(Exception):
    pass


def call_signing(file_path, endpoint, auth):
    """Get the jar signature and send it to the signing server to be signed."""

    # We only want the (unique) temporary file name.
    with tempfile.NamedTemporaryFile() as temp_file:
        temp_filename = temp_file.name

    # Extract jar signature.
    jar = JarExtractor(path=file_path,
                       outpath=temp_filename,
                       omit_signature_sections=True,
                       extra_newlines=True)

    response = requests.post(endpoint,
                             auth=auth,
                             files={'file': (u'mozilla.sf',
                                    unicode(jar.signatures))})

    if response.status_code != 200:
        msg = u'Posting to add-on signing failed: {0}'.format(response.reason)
        raise SigningError(msg)

    pkcs7 = b64decode(json.loads(response.content)['mozilla.rsa'])
    jar.make_signed(pkcs7, sigpath=u'mozilla')
    shutil.move(temp_filename, file_path)

    print "{0} signed!".format(file_path)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("filename", help="File to sign")

    parser.add_argument("-s", "--signer",
                        help="Signing Server Endpoint i.e."
                        "https://localhost/1.0/sign_app",
                        action="store", required=True)

    parser.add_argument("-u", "--username",
                        help="The username to authenticate with",
                        action="store")

    args = parser.parse_args()

    username = args.username or raw_input("Enter username: ")
    password = getpass.getpass("Enter password: ")

    call_signing(args.filename, args.signer, (username, password))


if __name__ == '__main__':
    main()
