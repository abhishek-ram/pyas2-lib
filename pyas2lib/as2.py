"""Define the core functions/classes of the pyas2 package."""
import logging
import hashlib
import binascii
import traceback
from dataclasses import dataclass
from email import encoders
from email import message as email_message
from email import message_from_bytes as parse_mime
from email import utils as email_utils
from email.mime.multipart import MIMEMultipart
from oscrypto import asymmetric

from pyas2lib.cms import (
    compress_message,
    decompress_message,
    decrypt_message,
    encrypt_message,
    sign_message,
    verify_message,
)
from pyas2lib.constants import (
    AS2_VERSION,
    ASYNCHRONOUS_MDN,
    DIGEST_ALGORITHMS,
    EDIINT_FEATURES,
    ENCRYPTION_ALGORITHMS,
    MDN_CONFIRM_TEXT,
    MDN_FAILED_TEXT,
    MDN_MODES,
    SYNCHRONOUS_MDN,
)
from pyas2lib.exceptions import (
    AS2Exception,
    DuplicateDocument,
    ImproperlyConfigured,
    InsufficientSecurityError,
    IntegrityError,
    MDNNotFound,
    PartnerNotFound,
)
from pyas2lib.utils import (
    canonicalize,
    extract_first_part,
    make_mime_boundary,
    mime_to_bytes,
    pem_to_der,
    quote_as2name,
    split_pem,
    unquote_as2name,
    verify_certificate_chain,
)

logger = logging.getLogger("pyas2lib")


@dataclass
class Organization:
    """
    Class represents an AS2 organization and defines the certificates and
    settings to be used when sending and receiving messages.

    :param as2_name: The unique AS2 name for this organization

    :param sign_key: A byte string of the pkcs12 encoded key pair
        used for signing outbound messages and MDNs.

    :param sign_key_pass: The password for decrypting the `sign_key`

    :param decrypt_key:  A byte string of the pkcs12 encoded key pair
        used for decrypting inbound messages.

    :param decrypt_key_pass: The password for decrypting the `decrypt_key`

    :param mdn_url: The URL where the receiver is expected to post
        asynchronous MDNs.

    :param domain:
        Optional domain if given provides the portion of the message id
        after the '@'.  It defaults to the locally defined hostname.
    """

    as2_name: str
    sign_key: bytes = None
    sign_key_pass: str = None
    decrypt_key: bytes = None
    decrypt_key_pass: str = None
    mdn_url: str = None
    mdn_confirm_text: str = MDN_CONFIRM_TEXT
    domain: str = None

    def __post_init__(self):
        """Run the post initialisation checks for this class."""
        # Load the signature and decryption keys
        if self.sign_key:
            self.sign_key = self.load_key(self.sign_key, self.sign_key_pass)

        if self.decrypt_key:
            self.decrypt_key = self.load_key(self.decrypt_key, self.decrypt_key_pass)

    @staticmethod
    def load_key(key_str: bytes, key_pass: str):
        """Function to load password protected key file in p12 or pem format."""

        try:
            # First try to parse as a p12 file
            key, cert, _ = asymmetric.load_pkcs12(key_str, key_pass)
        except ValueError as e:
            # If it fails due to invalid password raise error here
            if e.args[0] == "Password provided is invalid":
                raise AS2Exception("Password not valid for Private Key.") from e

            # if not try to parse as a pem file
            key, cert = None, None
            for kc in split_pem(key_str):
                try:
                    cert = asymmetric.load_certificate(kc)
                except (ValueError, TypeError) as e:
                    try:
                        key = asymmetric.load_private_key(kc, key_pass)
                    except OSError:
                        raise AS2Exception(
                            "Invalid Private Key or password is not correct."
                        ) from e

        if not key or not cert:
            raise AS2Exception("Invalid Private key file or Public key not included.")

        return key, cert


@dataclass
class Partner:
    """
    Class represents an AS2 partner and defines the certificates and
    settings to be used when sending and receiving messages.

    :param as2_name: The unique AS2 name for this partner.

    :param verify_cert: A byte string of the certificate to be used for
        verifying signatures of inbound messages and MDNs.

    :param verify_cert_ca: A byte string of the ca certificate if any of
        the verification cert

    :param encrypt_cert: A byte string of the certificate to be used for
        encrypting outbound message.

    :param encrypt_cert_ca: A byte string of the ca certificate if any of
        the encryption cert

    :param validate_certs: Set this flag to `False` to disable validations of
        the encryption and verification certificates. (default `True`)

    :param compress: Set this flag to `True` to compress outgoing
        messages. (default `False`)

    :param sign: Set this flag to `True` to sign outgoing
        messages. (default `False`)

    :param digest_alg: The digest algorithm to be used for generating the
        signature. (default "sha256")

    :param encrypt: Set this flag to `True` to encrypt outgoing
        messages. (default `False`)

    :param enc_alg:
        The encryption algorithm to be used. (default `"tripledes_192_cbc"`)

    :param mdn_mode: The mode to be used for receiving the MDN.
        Set to `None` for no MDN, `'SYNC'` for synchronous and `'ASYNC'`
        for asynchronous. (default `None`)

    :param mdn_digest_alg: The digest algorithm to be used by the receiver
        for signing the MDN. Use `None` for unsigned MDN. (default `None`)

    :param mdn_confirm_text: The text to be used in the MDN for successfully
        processed messages received from this partner.

    """

    as2_name: str
    verify_cert: bytes = None
    verify_cert_ca: bytes = None
    encrypt_cert: bytes = None
    encrypt_cert_ca: bytes = None
    validate_certs: bool = True
    compress: bool = False
    encrypt: bool = False
    enc_alg: str = "tripledes_192_cbc"
    sign: bool = False
    digest_alg: str = "sha256"
    mdn_mode: str = None
    mdn_digest_alg: str = None
    mdn_confirm_text: str = MDN_CONFIRM_TEXT
    ignore_self_signed: bool = True

    def __post_init__(self):
        """Run the post initialisation checks for this class."""

        # Validations
        if self.digest_alg and self.digest_alg not in DIGEST_ALGORITHMS:
            raise ImproperlyConfigured(
                f"Unsupported Digest Algorithm {self.digest_alg}, must be "
                f"one of {DIGEST_ALGORITHMS}"
            )

        if self.enc_alg and self.enc_alg not in ENCRYPTION_ALGORITHMS:
            raise ImproperlyConfigured(
                f"Unsupported Encryption Algorithm {self.enc_alg}, must be "
                f"one of {ENCRYPTION_ALGORITHMS}"
            )

        if self.mdn_mode and self.mdn_mode not in MDN_MODES:
            raise ImproperlyConfigured(
                f"Unsupported MDN Mode {self.mdn_mode}, must be " f"one of {MDN_MODES}"
            )

        if self.mdn_digest_alg and self.mdn_digest_alg not in DIGEST_ALGORITHMS:
            raise ImproperlyConfigured(
                f"Unsupported MDN Digest Algorithm {self.mdn_digest_alg}, "
                f"must be one of {DIGEST_ALGORITHMS}"
            )

    def load_verify_cert(self):
        """Load the verification certificate of the partner and returned the parsed cert."""
        if self.validate_certs:
            # Convert the certificate to DER format
            cert = pem_to_der(self.verify_cert, return_multiple=False)

            # Convert the ca certificate to DER format
            if self.verify_cert_ca:
                trust_roots = pem_to_der(self.verify_cert_ca)
            else:
                trust_roots = []

            # Verify the certificate against the trusted roots
            verify_certificate_chain(
                cert, trust_roots, ignore_self_signed=self.ignore_self_signed
            )

        return asymmetric.load_certificate(self.verify_cert)

    def load_encrypt_cert(self):
        """Load the encryption certificate of the partner and returned the parsed cert."""
        if self.validate_certs:
            # Convert the certificate to DER format
            cert = pem_to_der(self.encrypt_cert, return_multiple=False)

            # Convert the ca certificate to DER format
            if self.encrypt_cert_ca:
                trust_roots = pem_to_der(self.encrypt_cert_ca)
            else:
                trust_roots = []

            # Verify the certificate against the trusted roots
            verify_certificate_chain(
                cert, trust_roots, ignore_self_signed=self.ignore_self_signed
            )

        return asymmetric.load_certificate(self.encrypt_cert)


class Message:
    """Class for handling AS2 messages. Includes functions for both
    parsing and building messages.
    """

    def __init__(self, sender=None, receiver=None):
        """
        :param sender:
            An object of type <pyas2lib.as2.Organization>, representing the
            sender of the message.

        :param receiver:
            An object of type <pyas2lib.as2.Partner>, representing the
            receiver of the message .
        """
        self.sender = sender
        self.receiver = receiver
        self.compressed = False
        self.signed = False
        self.digest_alg = None
        self.encrypted = False
        self.enc_alg = None
        self.message_id = None
        self.payload = None
        self.mic = None

    @property
    def content(self):
        """Function returns the body of the as2 payload as a bytes object"""
        if self.payload is None:
            return ""

        if self.payload.is_multipart():
            message_bytes = mime_to_bytes(self.payload)
            boundary = b"--" + self.payload.get_boundary().encode("utf-8")
            temp = message_bytes.split(boundary)
            temp.pop(0)
            return boundary + boundary.join(temp)

        content = self.payload.get_payload(decode=True)
        return content

    @property
    def headers(self):
        """Return the headers in the payload as a dictionary."""
        if self.payload:
            return dict(self.payload.items())
        return {}

    @property
    def headers_str(self):
        """Return the headers in the payload as a string."""
        message_header = ""
        if self.payload:
            for k, v in self.headers.items():
                message_header += f"{k}: {v}\r\n"
        return message_header.encode("utf-8")

    def build(
        self,
        data,
        filename=None,
        subject="AS2 Message",
        content_type="application/edi-consent",
        additional_headers=None,
        disposition_notification_to="no-reply@pyas2.com",
    ):

        """Function builds the AS2 message. Compresses, signs and encrypts
        the payload if applicable.

        :param data: A byte string of the data to be transmitted.

        :param filename:
            Optional filename to be included in the Content-disposition header.

        :param subject:
            The subject for the AS2 message, used by some AS2 servers for
            additional routing of messages. (default "AS2 Message")

        :param content_type:
            The content type for the AS2 message, to be used in the MIME
            header. (default "application/edi-consent")

        :param additional_headers:
            Any additional headers to be included as part of the AS2 message.

        :param disposition_notification_to:
            Email address for disposition-notification-to header entry.
            (default "no-reply@pyas2.com")
        """

        # Validations
        assert isinstance(data, bytes), "Parameter data must be of bytes type."

        additional_headers = additional_headers if additional_headers else {}
        assert isinstance(additional_headers, dict)

        if self.receiver.sign and not self.sender.sign_key:
            raise ImproperlyConfigured(
                "Signing of messages is enabled but sign key is not set for the sender."
            )

        if self.receiver.encrypt and not self.receiver.encrypt_cert:
            raise ImproperlyConfigured(
                "Encryption of messages is enabled but encrypt key is not set for the receiver."
            )

        # Generate message id using UUID 1 as it uses both hostname and time
        self.message_id = (
            email_utils.make_msgid(domain=self.sender.domain).lstrip("<").rstrip(">")
        )

        # Set up the message headers
        as2_headers = {
            "AS2-Version": AS2_VERSION,
            "ediint-features": EDIINT_FEATURES,
            "Message-ID": f"<{self.message_id}>",
            "AS2-From": quote_as2name(self.sender.as2_name),
            "AS2-To": quote_as2name(self.receiver.as2_name),
            "Subject": subject,
            "Date": email_utils.formatdate(localtime=True),
        }
        as2_headers.update(additional_headers)

        # Read the input and convert to bytes if value is unicode/str
        # using utf-8 encoding and finally Canonicalize the payload
        self.payload = email_message.Message()
        self.payload.set_payload(data)
        self.payload.set_type(content_type)

        if content_type.lower().startswith("application/octet-stream"):
            self.payload["Content-Transfer-Encoding"] = "binary"
        else:
            encoders.encode_7or8bit(self.payload)

        if filename:
            self.payload.add_header(
                "Content-Disposition", "attachment", filename=filename
            )
        del self.payload["MIME-Version"]

        if self.receiver.compress:
            self.compressed = True
            compressed_message = email_message.Message()
            compressed_message.set_type("application/pkcs7-mime")
            compressed_message.set_param("name", "smime.p7z")
            compressed_message.set_param("smime-type", "compressed-data")
            compressed_message.add_header(
                "Content-Disposition", "attachment", filename="smime.p7z"
            )
            compressed_message.add_header("Content-Transfer-Encoding", "binary")
            compressed_message.set_payload(
                compress_message(mime_to_bytes(self.payload))
            )
            self.payload = compressed_message

            logger.debug(
                f"Compressed message {self.message_id} payload as:\n{mime_to_bytes(self.payload)}"
            )

        if self.receiver.sign:
            self.signed, self.digest_alg = True, self.receiver.digest_alg
            signed_message = MIMEMultipart(
                "signed", protocol="application/pkcs7-signature"
            )
            del signed_message["MIME-Version"]
            signed_message.attach(self.payload)

            # Calculate the MIC Hash of the message to be verified
            mic_content = canonicalize(self.payload)
            digest_func = hashlib.new(self.digest_alg)
            digest_func.update(mic_content)
            self.mic = binascii.b2a_base64(digest_func.digest()).strip()

            # Create the signature mime message
            signature = email_message.Message()
            signature.set_type("application/pkcs7-signature")
            signature.set_param("name", "smime.p7s")
            signature.set_param("smime-type", "signed-data")
            signature.add_header(
                "Content-Disposition", "attachment", filename="smime.p7s"
            )
            del signature["MIME-Version"]
            signature_data = sign_message(
                mic_content, self.digest_alg, self.sender.sign_key
            )
            signature.set_payload(signature_data)
            encoders.encode_base64(signature)

            signed_message.set_param("micalg", self.digest_alg)
            signed_message.attach(signature)
            self.payload = signed_message

            logger.debug(
                f"Signed message {self.message_id} payload as:\n{mime_to_bytes(self.payload)}"
            )

        if self.receiver.encrypt:
            self.encrypted, self.enc_alg = True, self.receiver.enc_alg
            encrypted_message = email_message.Message()
            encrypted_message.set_type("application/pkcs7-mime")
            encrypted_message.set_param("name", "smime.p7m")
            encrypted_message.set_param("smime-type", "enveloped-data")
            encrypted_message.add_header(
                "Content-Disposition", "attachment", filename="smime.p7m"
            )
            encrypted_message.add_header("Content-Transfer-Encoding", "binary")
            encrypt_cert = self.receiver.load_encrypt_cert()
            encrypted_data = encrypt_message(
                mime_to_bytes(self.payload), self.enc_alg, encrypt_cert
            )
            encrypted_message.set_payload(encrypted_data)

            self.payload = encrypted_message
            logger.debug(
                f"Encrypted message {self.message_id} payload as:\n{mime_to_bytes(self.payload)}"
            )

        if self.receiver.mdn_mode:
            as2_headers["disposition-notification-to"] = disposition_notification_to
            if self.receiver.mdn_digest_alg:
                as2_headers["disposition-notification-options"] = (
                    f"signed-receipt-protocol=required, pkcs7-signature; "
                    f"signed-receipt-micalg=optional, {self.receiver.mdn_digest_alg}"
                )
            if self.receiver.mdn_mode == "ASYNC":
                if not self.sender.mdn_url:
                    raise ImproperlyConfigured(
                        "MDN URL must be set in the organization when MDN mode is set to ASYNC"
                    )
                as2_headers["receipt-delivery-option"] = self.sender.mdn_url

        # Update the headers of the final payload and set its boundary
        for k, v in as2_headers.items():
            if self.payload.get(k):
                self.payload.replace_header(k, v)
            else:
                self.payload.add_header(k, v)

        if self.payload.is_multipart():
            self.payload.set_boundary(make_mime_boundary())

    def _decompress_data(self, payload):
        if (
            payload.get_content_type() == "application/pkcs7-mime"
            and payload.get_param("smime-type") == "compressed-data"
        ):
            logger.debug(
                f"Decompressing message {self.message_id} payload :\n"
                f"{mime_to_bytes(self.payload)}"
            )
            compressed_data = payload.get_payload(decode=True)
            decompressed_data = decompress_message(compressed_data)
            return True, parse_mime(decompressed_data)

        return False, payload

    def parse(self, raw_content, find_org_cb, find_partner_cb, find_message_cb=None):
        """Function parses the RAW AS2 message; decrypts, verifies and
        decompresses it and extracts the payload.

        :param raw_content:
            A byte string of the received HTTP headers followed by the body.

        :param find_org_cb:
            A callback the returns an Organization object if exists. The
            as2-to header value is passed as an argument to it.

        :param find_partner_cb:
            A callback the returns an Partner object if exists. The
            as2-from header value is passed as an argument to it.

        :param find_message_cb:
            An optional callback the returns an Message object if exists in
            order to check for duplicates. The message id and partner id is
            passed as arguments to it.

        :return:
            A three element tuple containing (status, (exception, traceback)
            , mdn). The status is a string indicating the status of the
            transaction. The exception is populated with any exception raised
            during processing and the mdn is an MDN object or None in case
            the partner did not request it.
        """

        # Parse the raw MIME message and extract its content and headers
        status, detailed_status, exception, mdn = "processed", None, (None, None), None
        self.payload = parse_mime(raw_content)
        as2_headers = {}
        for k, v in self.payload.items():
            k = k.lower()
            if k == "message-id":
                self.message_id = v.lstrip("<").rstrip(">")
            as2_headers[k] = v

        try:
            # Get the organization and partner for this transmission
            org_id = unquote_as2name(as2_headers["as2-to"])
            self.receiver = find_org_cb(org_id)
            if not self.receiver:
                raise PartnerNotFound(f"Unknown AS2 organization with id {org_id}")

            partner_id = unquote_as2name(as2_headers["as2-from"])
            self.sender = find_partner_cb(partner_id)
            if not self.sender:
                raise PartnerNotFound(f"Unknown AS2 partner with id {partner_id}")

            if find_message_cb and find_message_cb(self.message_id, partner_id):
                raise DuplicateDocument(
                    "Duplicate message received, message with this ID already processed."
                )

            if (
                self.sender.encrypt
                and self.payload.get_content_type() != "application/pkcs7-mime"
            ):
                raise InsufficientSecurityError(
                    f"Incoming messages from partner {partner_id} are must be encrypted "
                    f"but encrypted message not found."
                )

            if (
                self.payload.get_content_type() == "application/pkcs7-mime"
                and self.payload.get_param("smime-type") == "enveloped-data"
            ):
                logger.debug(
                    f"Decrypting message {self.message_id} payload :\n"
                    f"{mime_to_bytes(self.payload)}"
                )

                self.encrypted = True
                encrypted_data = self.payload.get_payload(decode=True)
                self.enc_alg, decrypted_content = decrypt_message(
                    encrypted_data, self.receiver.decrypt_key
                )

                self.payload = parse_mime(decrypted_content)

                if self.payload.get_content_type() == "text/plain":
                    self.payload = email_message.Message()
                    self.payload.set_payload(decrypted_content)
                    self.payload.set_type("application/edi-consent")

            # Check for compressed data here
            self.compressed, self.payload = self._decompress_data(self.payload)

            if (
                self.sender.sign
                and self.payload.get_content_type() != "multipart/signed"
            ):
                raise InsufficientSecurityError(
                    f"Incoming messages from partner {partner_id} are must be signed "
                    f"but signed message not found."
                )

            if self.payload.get_content_type() == "multipart/signed":
                logger.debug(
                    f"Verifying signed message {self.message_id} payload: \n"
                    f"{mime_to_bytes(self.payload)}"
                )
                self.signed = True

                # Split the message into signature and signed message
                signature = None
                signature_types = [
                    "application/pkcs7-signature",
                    "application/x-pkcs7-signature",
                ]
                for part in self.payload.walk():
                    if part.get_content_type() in signature_types:
                        signature = part.get_payload(decode=True)
                    else:
                        self.payload = part

                # Verify the message, first using raw message and if it fails
                # then convert to canonical form and try again
                mic_content = canonicalize(self.payload)
                verify_cert = self.sender.load_verify_cert()
                self.digest_alg = verify_message(mic_content, signature, verify_cert)

                # Calculate the MIC Hash of the message to be verified
                digest_func = hashlib.new(self.digest_alg)
                digest_func.update(mic_content)
                self.mic = binascii.b2a_base64(digest_func.digest()).strip()

            # Check for compressed data here
            if not self.compressed:
                self.compressed, self.payload = self._decompress_data(self.payload)

        except Exception as e:  # pylint: disable=W0703
            status = getattr(e, "disposition_type", "processed/Error")
            detailed_status = getattr(
                e, "disposition_modifier", "unexpected-processing-error"
            )
            exception = (e, traceback.format_exc())
            logger.error(f"Failed to parse AS2 message\n: {traceback.format_exc()}")

        # Update the payload headers with the original headers
        for k, v in as2_headers.items():
            preserve = [
                "content-type",
                "content-disposition",
                "content-transfer-encoding",
            ]
            if self.payload.get(k) and k.lower() not in preserve:
                del self.payload[k]
            self.payload.add_header(k, v)

        if as2_headers.get("disposition-notification-to"):
            mdn_mode = SYNCHRONOUS_MDN

            mdn_url = as2_headers.get("receipt-delivery-option")
            if mdn_url:
                mdn_mode = ASYNCHRONOUS_MDN

            digest_alg = as2_headers.get("disposition-notification-options")
            if digest_alg:
                digest_alg = digest_alg.split(";")[-1].split(",")[-1].strip()

            logger.debug(
                f"Building the MDN for message {self.message_id} with status {status} "
                f"and detailed-status {detailed_status}."
            )
            mdn = Mdn(mdn_mode=mdn_mode, mdn_url=mdn_url, digest_alg=digest_alg)
            mdn.build(message=self, status=status, detailed_status=detailed_status)

        return status, exception, mdn


class Mdn:
    """Class for handling AS2 MDNs. Includes functions for both
    parsing and building them.
    """

    def __init__(self, mdn_mode=None, digest_alg=None, mdn_url=None):
        self.message_id = None
        self.orig_message_id = None
        self.payload = None
        self.mdn_mode = mdn_mode
        self.digest_alg = digest_alg
        self.mdn_url = mdn_url

    @property
    def content(self):
        """Function returns the body of the mdn message as a byte string"""

        if self.payload is not None:
            message_bytes = mime_to_bytes(self.payload)
            boundary = b"--" + self.payload.get_boundary().encode("utf-8")
            temp = message_bytes.split(boundary)
            temp.pop(0)
            return boundary + boundary.join(temp)
        return ""

    @property
    def headers(self):
        """Return the headers in the payload as a dictionary."""
        if self.payload:
            return dict(self.payload.items())
        return {}

    @property
    def headers_str(self):
        """Return the headers in the payload as a string."""
        message_header = ""
        if self.payload:
            for k, v in self.headers.items():
                message_header += f"{k}: {v}\r\n"
        return message_header.encode("utf-8")

    def build(
        self,
        message,
        status,
        detailed_status=None,
        confirmation_text=MDN_CONFIRM_TEXT,
        failed_text=MDN_FAILED_TEXT,
    ):
        """Function builds and signs an AS2 MDN message.

        :param message: The received AS2 message for which this is an MDN.

        :param status: The status of processing of the received AS2 message.

        :param detailed_status: The optional detailed status of processing of the received AS2
        message. Used to give additional error info (default "None")

        :param confirmation_text: The confirmation message sent in the first part of the MDN.

        :param failed_text: The failure message sent in the first part of the failed MDN.
        """

        # Generate message id using UUID 1 as it uses both hostname and time
        domain = message.receiver.domain if message.receiver else None
        self.message_id = email_utils.make_msgid(domain=domain).lstrip("<").rstrip(">")
        self.orig_message_id = message.message_id

        # Set up the message headers
        mdn_headers = {
            "AS2-Version": AS2_VERSION,
            "ediint-features": EDIINT_FEATURES,
            "Message-ID": f"<{self.message_id}>",
            "AS2-From": quote_as2name(message.headers.get("as2-to")),
            "AS2-To": quote_as2name(message.headers.get("as2-from")),
            "Date": email_utils.formatdate(localtime=True),
            "user-agent": "pyAS2 Open Source AS2 Software",
        }

        # Set the confirmation text message here
        # overwrite with organization specific message
        if message.receiver and message.receiver.mdn_confirm_text:
            confirmation_text = message.receiver.mdn_confirm_text

        # overwrite with partner specific message
        if message.sender and message.sender.mdn_confirm_text:
            confirmation_text = message.sender.mdn_confirm_text

        if status != "processed":
            confirmation_text = failed_text

        self.payload = MIMEMultipart("report", report_type="disposition-notification")

        # Create and attach the MDN Text Message
        mdn_text = email_message.Message()
        mdn_text.set_payload(f"{confirmation_text}\r\n")
        mdn_text.set_type("text/plain")
        del mdn_text["MIME-Version"]
        encoders.encode_7or8bit(mdn_text)
        self.payload.attach(mdn_text)

        # Create and attache the MDN Report Message
        mdn_base = email_message.Message()
        mdn_base.set_type("message/disposition-notification")
        mdn_report = "Reporting-UA: pyAS2 Open Source AS2 Software\r\n"
        mdn_report += f'Original-Recipient: rfc822; {message.headers.get("as2-to")}\r\n'
        mdn_report += f'Final-Recipient: rfc822; {message.headers.get("as2-to")}\r\n'
        mdn_report += f"Original-Message-ID: <{message.message_id}>\r\n"
        mdn_report += f"Disposition: automatic-action/MDN-sent-automatically; {status}"
        if detailed_status:
            mdn_report += f": {detailed_status}"
        mdn_report += "\r\n"
        if message.mic:
            mdn_report += f"Received-content-MIC: {message.mic.decode()}, {message.digest_alg}\r\n"
        mdn_base.set_payload(mdn_report)
        del mdn_base["MIME-Version"]
        encoders.encode_7or8bit(mdn_base)
        self.payload.attach(mdn_base)

        logger.debug(
            f"MDN report for message {message.message_id} created:\n{mime_to_bytes(mdn_base)}"
        )

        # Sign the MDN if it is requested by the sender
        if (
            message.headers.get("disposition-notification-options")
            and message.receiver
            and message.receiver.sign_key
        ):
            self.digest_alg = (
                message.headers["disposition-notification-options"]
                .split(";")[-1]
                .split(",")[-1]
                .strip()
                .replace("-", "")
            )
            signed_mdn = MIMEMultipart("signed", protocol="application/pkcs7-signature")
            del signed_mdn["MIME-Version"]
            signed_mdn.attach(self.payload)

            # Create the signature mime message
            signature = email_message.Message()
            signature.set_type("application/pkcs7-signature")
            signature.set_param("name", "smime.p7s")
            signature.set_param("smime-type", "signed-data")
            signature.add_header(
                "Content-Disposition", "attachment", filename="smime.p7s"
            )
            del signature["MIME-Version"]

            signed_data = sign_message(
                canonicalize(self.payload), self.digest_alg, message.receiver.sign_key
            )
            signature.set_payload(signed_data)
            encoders.encode_base64(signature)

            signed_mdn.set_param("micalg", self.digest_alg)
            signed_mdn.attach(signature)

            self.payload = signed_mdn
            logger.debug(f"Signing the MDN for message {message.message_id}")

        # Update the headers of the final payload and set message boundary
        for k, v in mdn_headers.items():
            if self.payload.get(k):
                self.payload.replace_header(k, v)
            else:
                self.payload.add_header(k, v)
        self.payload.set_boundary(make_mime_boundary())
        logger.debug(
            f"MDN generated for message {message.message_id} with "
            f"content:\n {mime_to_bytes(self.payload)}"
        )

    def parse(self, raw_content, find_message_cb):
        """Function parses the RAW AS2 MDN, verifies it and extracts the
        processing status of the orginal AS2 message.

        :param raw_content:
            A byte string of the received HTTP headers followed by the body.

        :param find_message_cb:
            A callback the must returns the original Message Object. The
            original message-id and original recipient AS2 ID are passed
            as arguments to it.

        :returns:
            A two element tuple containing (status, detailed_status). The
            status is a string indicating the status of the transaction. The
            optional detailed_status gives additional information about the
            processing status.
        """

        status, detailed_status = None, None
        try:
            self.payload = parse_mime(raw_content)
            self.orig_message_id, orig_recipient = self.detect_mdn()

            # Call the find message callback which should return a Message instance
            orig_message = find_message_cb(self.orig_message_id, orig_recipient)

            # Extract the headers and save it
            mdn_headers = {}
            for k, v in self.payload.items():
                k = k.lower()
                if k == "message-id":
                    self.message_id = v.lstrip("<").rstrip(">")
                mdn_headers[k] = v

            if (
                orig_message.receiver.mdn_digest_alg
                and self.payload.get_content_type() != "multipart/signed"
            ):
                status = "failed/Failure"
                detailed_status = "Expected signed MDN but unsigned MDN returned"
                return status, detailed_status

            if self.payload.get_content_type() == "multipart/signed":
                logger.debug(f"Verifying signed MDN: \n{mime_to_bytes(self.payload)}")
                message_boundary = ("--" + self.payload.get_boundary()).encode("utf-8")

                # Extract the signature and the signed payload
                signature = None
                signature_types = [
                    "application/pkcs7-signature",
                    "application/x-pkcs7-signature",
                ]
                for part in self.payload.walk():
                    if part.get_content_type() in signature_types:
                        signature = part.get_payload(decode=True)
                    elif part.get_content_type() == "multipart/report":
                        self.payload = part

                # Verify the message, first using raw message and if it fails
                # then convert to canonical form and try again
                mic_content = extract_first_part(raw_content, message_boundary)
                verify_cert = orig_message.receiver.load_verify_cert()
                try:
                    self.digest_alg = verify_message(
                        mic_content, signature, verify_cert
                    )
                except IntegrityError:
                    mic_content = canonicalize(self.payload)
                    self.digest_alg = verify_message(
                        mic_content, signature, verify_cert
                    )

            for part in self.payload.walk():
                if part.get_content_type() == "message/disposition-notification":
                    logger.debug(
                        f"MDN report for message {orig_message.message_id}:\n{part.as_string()}"
                    )

                    mdn = part.get_payload()[-1]
                    mdn_status = mdn["Disposition"].split(";").pop().strip().split(":")
                    status = mdn_status[0]
                    if status == "processed":
                        # Compare the original mic with the received mic
                        mdn_mic = mdn.get("Received-Content-MIC", "").split(",")[0]
                        if (
                            mdn_mic
                            and orig_message.mic
                            and mdn_mic != orig_message.mic.decode()
                        ):
                            status = "processed/warning"
                            detailed_status = "Message Integrity check failed."
                    else:
                        detailed_status = " ".join(mdn_status[1:]).strip()
        except MDNNotFound:
            status = "failed/Failure"
            detailed_status = "mdn-not-found"
        except Exception as e:  # pylint: disable=W0703
            status = "failed/Failure"
            detailed_status = f"Failed to parse received MDN. {e}"
            logger.error(f"Failed to parse AS2 MDN\n: {traceback.format_exc()}")
        return status, detailed_status

    def detect_mdn(self):
        """Function checks if the received raw message is an AS2 MDN or not.

        :raises MDNNotFound: If the received payload is not an MDN then this
        exception is raised.

        :return:
            A two element tuple containing (message_id, message_recipient). The
            message_id is the original AS2 message id and the message_recipient
            is the original AS2 message recipient.
        """
        mdn_message = None
        if self.payload.get_content_type() == "multipart/report":
            mdn_message = self.payload
        elif self.payload.get_content_type() == "multipart/signed":
            for part in self.payload.walk():
                if part.get_content_type() == "multipart/report":
                    mdn_message = self.payload

        if not mdn_message:
            raise MDNNotFound("No MDN found in the received message")

        message_id, message_recipient = None, None
        for part in mdn_message.walk():
            if part.get_content_type() == "message/disposition-notification":
                mdn = part.get_payload()[0]
                message_id = mdn.get("Original-Message-ID").strip("<>")
                message_recipient = None
                if "Original-Recipient" in mdn:
                    _, message_recipient = self._parse_message_recipient(
                        mdn["Original-Recipient"]
                    )
                elif "Final-Recipient" in mdn:
                    _, message_recipient = self._parse_message_recipient(
                        mdn["Final-Recipient"]
                    )
        return message_id, message_recipient

    @staticmethod
    def _parse_message_recipient(recipient: str):
        """
        Function parses the recipient values "Original-Recipient: rfc822; 012345678000"
        into address_type and
        message_recipient.
        :param recipient: example: "rfc822; 012345678000"
        :return: address_type: "rfc822", message_recipient: "012345678000"
        """
        if ";" in recipient:
            return recipient.split(";")[0].strip(), recipient.split(";")[1].strip()
        return None, recipient.strip()
