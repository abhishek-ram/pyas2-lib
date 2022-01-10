# pyas2-lib

[![pypi package](https://img.shields.io/pypi/v/pyas2lib.svg)](https://pypi.python.org/pypi/pyas2lib/)
[![Run Tests](https://github.com/abhishek-ram/pyas2-lib/actions/workflows/run-tests.yml/badge.svg?branch=master&event=push)](https://github.com/abhishek-ram/pyas2-lib/actions/workflows/run-tests.yml?query=branch%3Amaster++)
[![codecov](https://codecov.io/gh/abhishek-ram/pyas2-lib/branch/master/graph/badge.svg)](https://codecov.io/gh/abhishek-ram/pyas2-lib)

A pure python library for building and parsing message as part of the AS2 messaging protocol. The message definitions follow the AS2 version 1.2 as defined in the [RFC 4130][1].The library is intended to decouple the message construction/deconstruction from the web server/client implementation. The following functionality is part of this library:
   
* Compress, Sign and Encrypt the payload to be transmitted.
* Building the MIME Message from the processed payload.
* Building a signed MDN Messages for a received payload.
* Parsing a received MIME data and identifying if it as a Message or MDN. 
* Decompress, Decrypt and Verify Signature of the received payload.
* Verify Signature of the received MDN and extract original message status. 


## Basic Usage

Let us take a look at how we can use this library for building and parsing of AS2 Messages. 

### Setup

* First we would need to setup an organization and a partner
```python
from pyas2lib.as2 import Organization, Partner

my_org = Organization(
    as2_name='my_unique_id',  # Unique AS2 Id for this organization
    sign_key=b'signature_key_bytes',  # PEM/DER encoded private key for signature
    sign_key_pass='password',  # Password private key for signature
    decrypt_key=b'decrypt_key_bytes',  # PEM/DER encoded private key for decryption
    decrypt_key_pass='password'  # Password private key for decryption
)

a_partner = Partner(
    as2_name='partner_unique_id',  # Unique AS2 Id of your partner
    sign=True,  # Set to true for signing the message
    verify_cert=b'verify_cert_bytes',  # PEM/DER encoded certificate for verifying partner signatures
    encrypt=True,  # Set to true for encrypting the message
    encrypt_cert=b'encrypt_cert_bytes',  # PEM/DER encoded certificate for encrypting messages
    mdn_mode='SYNC',  # Expect to receive synchronous MDNs from this partner
    mdn_digest_alg='sha256'  # Expect signed MDNs to be returned by this partner
)

``` 

### Sending a message to your partner

* The partner is now setup we can build and AS2 message
```python
from pyas2lib.as2 import Message

msg = Message(sender=my_org, receiver=a_partner)
msg.build(b'data_to_transmit')

```
* The message is built and now `msg.content` holds the message body and `message.header` dictionary holds the message headers. These need to be passed to any http library for HTTP POSTing to the partner.
* We expect synchronous MDNs so we need to process the response to our HTTP POST
```python
from pyas2lib.as2 import Mdn

msg_mdn = Mdn()  # Initialize an Mdn object

# Call the parse method with the HTTP response headers + content and a function that returns the related `pyas2lib.as2.Messsage` object.
status, detailed_status = msg_mdn.parse(b'response_data_with_headers', find_message_func)
```
* We parse the response mdn to get the status and detailed status of the message that was transmitted.

### Receiving a message from your partner

* We need to setup and HTTP server with an endpoint for receiving POST requests fro your partner.
* When a requests is received we need to first check if this is an Async MDN
```python
from pyas2lib.as2 import Mdn

msg_mdn = Mdn()  # Initialize an Mdn object
# Call the parse method with the HTTP request headers + content and a function the returns the related `pyas2lib.as2.Messsage` object.
status, detailed_status = msg_mdn.parse(request_body, find_message_fumc)
```
* If this is an Async MDN it will return the status of the original message.
* In case the request is not an MDN then `pyas2lib.exceptions.MDNNotFound` is raised, which needs to be catched and parse the request as a message.
```python
from pyas2lib.as2 import Message

msg = Message()
# Call the parse method with the HTTP request headers + content, a function to return the the related `pyas2lib.as2.Organization` object, a function to return the `pyas2lib.as2.Partner` object and a function to check for duplicates.
status, exception, mdn = msg.parse(
    request_body, find_organization, find_partner, check_duplicate_msg)
```
* The parse function returns a 3 element tuple; the status of parsing, exception if any raised during parsing and an `pyas2lib.as2.Mdn` object for the message.
* If the `mdn.mdn_mode` is `SYNC` then the `mdn.content` and `mdn.header` must be returned in the response.
* If the `mdn.mdn_mode` is `ASYNC` then the mdn must be saved for later processing.  

## Contribute

1. Check for open issues or open a fresh issue to start a discussion around a feature idea or a bug.
1. Fork [the repository][2] on GitHub to start making your changes to the **master** branch (or branch off of it).
1. Create your feature branch: `git checkout -b my-new-feature`
1. Commit your changes: `git commit -am 'Add some feature'`
1. Push to the branch: `git push origin my-new-feature`
1. Send a pull request and bug the maintainer until it gets merged and published. :) Make sure to add yourself to [AUTHORS][3].

[1]: https://www.ietf.org/rfc/rfc4130.txt
[2]: https://github.com/abhishek-ram/pyas2-lib
[3]: https://github.com/abhishek-ram/pyas2-lib/blob/master/AUTHORS.md
