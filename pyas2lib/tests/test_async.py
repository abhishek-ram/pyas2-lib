import pytest
from pyas2lib import as2
import os

from pyas2lib.tests import TEST_DIR

with open(os.path.join(TEST_DIR, "payload.txt"), "rb") as fp:
    test_data = fp.read()

with open(os.path.join(TEST_DIR, "cert_test.p12"), "rb") as fp:
    private_key = fp.read()

with open(os.path.join(TEST_DIR, "cert_test_public.pem"), "rb") as fp:
    public_key = fp.read()

org = as2.Organization(
    as2_name="some_organization",
    sign_key=private_key,
    sign_key_pass="test",
    decrypt_key=private_key,
    decrypt_key_pass="test",
)
partner = as2.Partner(
    as2_name="some_partner",
    verify_cert=public_key,
    encrypt_cert=public_key,
)


async def afind_org(headers):
    return org


async def afind_partner(headers):
    return partner


async def afind_duplicate_message(message_id, message_recipient):
    return True


async def afind_org_partner(as2_org, as2_partner):
    return org, partner


@pytest.mark.asyncio
async def test_duplicate_message_async():
    """Test case where a duplicate message is sent to the partner using async callbacks"""

    # Build an As2 message to be transmitted to partner
    partner.sign = True
    partner.encrypt = True
    partner.mdn_mode = as2.SYNCHRONOUS_MDN
    out_message = as2.Message(org, partner)
    out_message.build(test_data)

    # Parse the generated AS2 message as the partner
    raw_out_message = out_message.headers_str + b"\r\n" + out_message.content
    in_message = as2.Message()
    _, _, mdn = await in_message.aparse(
        raw_out_message,
        find_org_cb=afind_org,
        find_partner_cb=afind_partner,
        find_message_cb=afind_duplicate_message,
    )

    out_mdn = as2.Mdn()
    status, detailed_status = await out_mdn.aparse(
        mdn.headers_str + b"\r\n" + mdn.content,
        find_message_cb=lambda x, y: out_message,
    )
    assert status == "processed/Warning"
    assert detailed_status == "duplicate-document"


@pytest.mark.asyncio
async def test_async_partnership():
    """Test Async Partnership callback"""

    # Build an As2 message to be transmitted to partner
    out_message = as2.Message(org, partner)
    out_message.build(test_data)
    raw_out_message = out_message.headers_str + b"\r\n" + out_message.content

    # Parse the generated AS2 message as the partner
    in_message = as2.Message()
    status, _, _ = await in_message.aparse(
        raw_out_message, find_org_partner_cb=afind_org_partner
    )

    # Compare contents of the input and output messages
    assert status == "processed"
