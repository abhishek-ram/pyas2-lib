# Release History

## 1.4.4 - 2024-

* feat: added partnership lookup function 
* feat: added support for async callback functions
* feat: added support for optional key encryption algorithm rsaes_oaep for encryption and decryption

## 1.4.3 - 2023-01-25

* fix: update pyopenssl version to resolve pyca/cryptography#7959

## 1.4.2 - 2022-12-11

* fix: update the black version to fix github ci pipeline
* feat: added partner setting to force canonicalize binary
* fix: freeze the version of pyflakes to resolve klen/pylama#224
* feat: update the versions of oscrypt and asn1crypto
* fix: Use SMIMECapabilites from asn1crypto instead of the custom class (needed due to asn1crypto upgrade)

## 1.4.1 - 2022-02-06

* fix: freezing pylama version to avoid breaking changes
* feat: option to pass custom domain for AS2 message-id generation

## 1.4.0 - 2022-02-06

* Handle the case where non utf-8 characters are present in the certificate
* Add support for python 3.10
* Move to GitHub actions for running automated tests
* Fix broken tests due to expired certs (#39)
* Preserve content headers on enveloped data (#36)
* When address-type is not specified, only use provided value (#34)
* Normalize digest algorithm to make it more compatible (#32)

## 1.3.3 - 2021-01-17
* Update the versions of asn1crypto, oscrypto and pyOpenSSL

## 1.3.2 - 2020-11-01
* Use `signature_algo` attribute when detecting the signature algorithm
* Raise exception when unknown `digest_alg` is passed to the sign function
* Add proper support for handling binary messages
* Look for `Final-Recipient` if `Original-Recipient` is not present in the MDN
* Remove support for python 3.6
* Fix linting and change the linter to pylava

## 1.3.1 - 2020-04-12
* Use correct format for setting dataclasses requirement for python 3.6

## 1.3.0 - 2020-04-05
* Fix and update the SMIME capabilities in the Signed attributes of a signature
* Update the versions of crypto dependencies and related changes
* Use black and pylama as code formatter and linter
* Increase test coverage and add support for python 3.8

## 1.2.2 - 2019-06-26
* Handle MDNNotfound correctly when parsing an mdn

## 1.2.1 - 2019-06-25
* Handle exceptions raised when parsing signed attributes in a signature https://github.com/abhishek-ram/django-pyas2/issues/13
* Add more debug logs during build and parse
* Catch errors in MDN parsing and handle accordingly

## 1.2.0 - 2019-06-12

* Use f-strings for string formatting.
* Use HTTP email policy for flattening email messages.
* Add proper support for other encryption algos.
* Use dataclasses for organization and partner. 
* Remove support for python 3.5.
* Add utility function for extracting info from certificates.

## 1.1.1 - 2019-06-03

* Remove leftover print statement.
* Add utility for extracting public certificate information.

## 1.1.0 - 2019-04-30

* Handle cases where compression is done before signing.
* Add support for additional encryption algorithms.
* Use binary encoding for encryption and signatures.
* Look for `application/x-pkcs7-signature` when verifying signatures.
* Remove support for Python 2.

## 1.0.3 - 2018-05-01

* Remove unnecessary conversions to bytes.

## 1.0.2 - 2018-05-01

* Fix an issue with message decompression.
* Add optional callback for checking duplicate messages in parse
* Add test cases for decompression and duplicate errors

## 1.0.1 - 2018-04-22

* Check for incorrect passphrase when loading the private key.
* Change field name from `as2_id` to `as2_name` in org and partner
* Change name of class from `MDN` to `Mdn`
* Fix couple of validation issues when loading partner
* Return the traceback along with the exception when parsing messages
* Fix the mechanism for loading and validation partner certs

## 1.0.0 - 2018-02-15

* Initial release.
