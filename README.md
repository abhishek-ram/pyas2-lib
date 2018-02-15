# pyas2-lib

[![pypi package](https://img.shields.io/pypi/v/pyas2lib.svg)](https://pypi.python.org/pypi/pyas2lib/)
[![Build Status](https://travis-ci.org/abhishek-ram/pyas2-lib.svg?branch=master)](https://travis-ci.org/abhishek-ram/pyas2-lib) 
[![codecov](https://codecov.io/gh/abhishek-ram/pyas2-lib/branch/master/graph/badge.svg)](https://codecov.io/gh/abhishek-ram/pyas2-lib)

A pure python library for building and parsing message as part of the AS2 messaging protocol. The message definitions follow the AS2 version 1.2 as defined in the [RFC 4130][1].The library is intended to decouple the message construction/deconstruction from the web server/client implementation. The following functionality is part of this library:
   
* Compress, Sign and Encrypt the payload to be transmitted.
* Building the MIME Message from the processed payload.
* Building a signed MDN Messages for a received payload.
* Parsing a received MIME data and identifying if it as a Message or MDN. 
* Decompress, Decrypt and Verify Signature of the received payload.
* Verify Signature of the received MDN and extract original message status. 
  
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