"""User signed certificate.

Implemented according to
`VIP192 <https://github.com/vechain/VIPs/blob/master/vips/VIP-192.md>`_
"""
import json
import sys
from typing import Optional

import voluptuous
from voluptuous import Schema

from thor_devkit.cry import blake2b256, secp256k1
from thor_devkit.cry.address import public_key_to_address

# Re-export, it was public interface
from thor_devkit.cry.utils import safe_tolowercase as safe_tolowercase
from thor_devkit.deprecation import renamed_function
from thor_devkit.exceptions import BadSignature
from thor_devkit.validation import address_type, hex_integer

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal, TypedDict
else:
    from typing import Final, Literal, TypedDict
if sys.version_info < (3, 11):
    from typing_extensions import NotRequired
else:
    from typing import NotRequired

__all__ = [
    # Main
    "Certificate",
    # Types
    "PayloadT",
    "CertificateT",
    # Schemas
    "PAYLOAD",
    "CERTIFICATE",
]


PAYLOAD: Final = Schema(
    {
        "type": str,
        "content": str,
    },
    required=True,
)
"""
Validation :external:class:`~voluptuous.schema_builder.Schema` for certificate payload.

:meta hide-value:

.. versionadded:: 2.0.0
"""


class PayloadT(TypedDict):
    """Type of Certificate ``payload`` parameter.

    .. versionadded:: 2.0.0
    """

    type: str  # noqa: A003
    """Payload type."""
    content: str
    """Payload content."""


CERTIFICATE: Final = Schema(
    {
        "purpose": voluptuous.Any("identification", "agreement"),
        "payload": PAYLOAD,
        "domain": str,
        "timestamp": int,
        "signer": address_type(),
        voluptuous.Optional("signature"): hex_integer(130),
    },
    required=True,
)
"""
Validation :external:class:`~voluptuous.schema_builder.Schema` for certificate payload.

:meta hide-value:

.. versionadded:: 2.0.0
"""


class CertificateT(TypedDict):
    """Type of Certificate body dictionary.

    .. versionadded:: 2.0.0
    """

    purpose: Literal["identification", "agreement"]
    """Purpose of certificate, can be ``identification`` or ``agreement``.

    Usage scenarios:

    Identification
        Request user to proof that he/she is the private key holder.

        In this scenario payload is not essential to the user.
    Agreement
        Request user to agree with an agreement by using user's private key to sign.

        In this scenario payload should contain the content such as Privacy policy
        and it is essential to the user.

    Use cases may be extended in future, see VIP192_ for details.
    """
    payload: PayloadT
    """Certificate payload."""
    domain: str
    """Domain for which certificate was issued."""
    timestamp: int
    """Issue time."""
    signer: str
    """Signer address, in ``0x...`` format."""
    signature: NotRequired[str]
    """Signature in ``0x...`` format, 65 bytes (as from :func:`cry.secp256k1.sign`)."""


class Certificate:
    """User signed certificate."""

    def __init__(
        self,
        purpose: Literal["identification", "agreement"],
        payload: PayloadT,
        domain: str,
        timestamp: int,
        signer: str,
        signature: Optional[str] = None,
    ):
        """Instantiate certificate from parameters.

        .. versionchanged:: 2.0.0
            :exc:`ValueError` not raised anymore, :exc:`~voluptuous.error.Invalid`
            is used instead.

        Parameters
        ----------
        purpose : str
            Certificate purpose.
        payload : PayloadT
            Dictionary of style { "type": str, "content": str}
        domain : str
            Certificate domain.
        timestamp : int
            Integer Unix timestamp.
        signer : str
            The signer address with ``0x`` prefix.
        signature : Optional[str], optional, default: None
            A ``secp256k1`` signed bytes, but turned into a
            ``'0x' + bytes.hex()`` format.

        Raises
        ------
        :exc:`~voluptuous.error.Invalid`
            When ``payload`` dictionary is malformed or parameters given are invalid.
        """
        # Validate
        payload = PAYLOAD(payload)

        body: CertificateT = {
            "purpose": purpose,
            "payload": payload,
            "domain": domain,
            "timestamp": timestamp,
            "signer": signer,
        }

        if signature:
            body["signature"] = signature

        # Validate and normalize
        self._body: CertificateT = CERTIFICATE(body)

    def to_dict(self) -> CertificateT:
        """Export certificate body as dictionary."""
        return self._body.copy()

    def encode(self) -> str:
        """
        Encode a certificate into json.

        .. versionadded:: 2.0.0

        Returns
        -------
        str
            The encoded string.
        """
        data = self.to_dict()
        data["signer"] = safe_tolowercase(data["signer"])
        sig = data.get("signature")
        if sig:
            data["signature"] = safe_tolowercase(sig)

        # separators=(',', ':') -> no whitespace compact string
        # sort_keys -> dict key is ordered.
        return json.dumps(data, separators=(",", ":"), sort_keys=True)

    def verify(self) -> Literal[True]:
        """Verify the signature of certificate.

        .. versionadded:: 2.0.0

        Raises
        ------
        BadSignature
            Signature does not match.
        ValueError
            Signature is absent or malformed.

        Returns
        -------
        Literal[True]
            Always True.
        """
        data = self.to_dict()

        # remove the signature, then encode.
        sig = data.pop("signature", "")
        if not sig:
            raise ValueError('the certificate needs a "signature" field.')

        the_encoded = Certificate(**data).encode()
        signing_hash, _ = blake2b256([the_encoded.encode()])
        pub_key = secp256k1.recover(signing_hash, bytes.fromhex(sig[2:]))
        signer = data["signer"]
        if "0x" + public_key_to_address(pub_key).hex() != safe_tolowercase(signer):
            raise BadSignature

        return True

    def is_valid(self) -> bool:
        """Check if the signature of certificate is valid.

        .. versionadded:: 2.0.0

        Returns
        -------
        bool
            Whether signature is valid.
        """
        try:
            return self.verify()
        except (ValueError, BadSignature):
            return False


@renamed_function("Certificate.encode")
def encode(cert: Certificate) -> str:
    """Encode a certificate into json.

    .. customtox-exclude::

    .. deprecated:: 2.0.0
        :func:`encode` module-level function is replaced by
        :meth:`Certificate.encode` method to conform with OOP standards.
    """
    return cert.encode()


@renamed_function("Certificate.verify")
def verify(cert: Certificate) -> Literal[True]:
    """Verify certificate signature.

    .. customtox-exclude::

    .. deprecated:: 2.0.0
        :func:`verify` module-level function is replaced by
        :meth:`Certificate.verify` method to conform with OOP standards.
    """
    return cert.verify()
