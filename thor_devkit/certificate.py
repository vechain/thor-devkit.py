"""User signed certificate.

`Documentation <https://github.com/vechain/VIPs/blob/master/vips/VIP-192.md>`__
"""
import json
import re
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
    "PAYLOAD",
    "PayloadT",
    "CERTIFICATE",
    "CertificateT",
    "Certificate",
]

SIGNATURE_PATTERN: Final = re.compile(r"^0x[0-9a-f]{130}$", re.I)
"""Signature must be hex-string with ``0x`` prefix."""


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
        "purpose": str,
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

    purpose: str
    """Purpose of certificate, e.g. ``identification``."""
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
        purpose: str,
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
        self._body = CERTIFICATE(body)

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
        elif len(sig) % 2 != 0:
            raise ValueError("the length of certificate signature must be even.")
        elif not SIGNATURE_PATTERN.match(sig):
            raise ValueError(
                "the signature of certificate doesn't match expected format"
            )

        the_encoded = Certificate(**data).encode()
        signing_hash, _ = blake2b256([the_encoded.encode()])
        pub_key = secp256k1.recover(signing_hash, bytes.fromhex(sig[2:]))
        signer = data["signer"]
        if "0x" + public_key_to_address(pub_key).hex() != safe_tolowercase(signer):
            raise BadSignature

        return True


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
