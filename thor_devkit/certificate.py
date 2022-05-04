"""
User signed certificate.

https://github.com/vechain/VIPs/blob/master/vips/VIP-192.md
"""
import json
import re
import sys
import warnings
from datetime import datetime
from typing import Optional, Union

from .cry import blake2b256, secp256k1
from .cry.address import public_key_to_address
from .exceptions import BadSignature
from .utils import safe_tolowercase

if sys.version_info < (3, 8):
    from typing_extensions import Final, Literal, TypedDict
else:
    from typing import Final, Literal, TypedDict
if sys.version_info < (3, 11):
    from typing_extensions import NotRequired
else:
    from typing import NotRequired


SIGNATURE_PATTERN: Final = re.compile("^0x[0-9a-f]+$", re.I)


class PayloadT(TypedDict):
    type: str  # noqa: A003
    content: str


class CertificateT(TypedDict):
    purpose: str
    payload: PayloadT
    domain: str
    timestamp: Union[int, datetime]
    signer: str
    signature: NotRequired[str]


class Certificate:
    def __init__(
        self,
        purpose: str,
        payload: PayloadT,
        domain: str,
        timestamp: Union[int, datetime],
        signer: str,
        signature: Optional[str] = None,
    ):
        """
        Certficate itself.

        .. versionchanged:: 2.0.0
            `datetime` object allowed for ``timestamp`` argument.

        Parameters
        ----------
        purpose : str
        payload : PayloadT
            Dictionary of style { "type": str, "content": str}
        domain : str
        timestamp : Union[int, datetime]
            Integer Unix timestamp or datetime.datetime object.
        signer : str
            0x... the signer address.
        signature : Optional[str], optional, default: None
            A secp256k1 signed bytes, but turned into a '0x' + bytes.hex() format
        """
        if not payload.get("type"):
            raise ValueError('payload needs a string field "type"')
        if not payload.get("content"):
            raise ValueError('payload needs a string field "content"')

        self._body: CertificateT = {
            "purpose": purpose,
            "payload": payload,
            "domain": domain,
            "timestamp": (
                round(timestamp.timestamp())
                if isinstance(timestamp, datetime)
                else timestamp
            ),
            "signer": signer,
        }

        if signature:
            self._body["signature"] = signature

    def to_dict(self) -> CertificateT:
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


def encode(cert: Certificate) -> str:
    """
    Encode a certificate into json.

    .. deprecated:: 2.0.0
        `encode` module-level function is replaced by
        `Certificate.encode` method to conform with OOP standards.
    """
    warnings.warn(
        DeprecationWarning(
            "Module-level `encode` function is deprecated. "
            "Use Certificate.encode method instead"
        )
    )
    return cert.encode()


def verify(cert: Certificate) -> Literal[True]:
    """
    Verify certificate signature.

    .. deprecated:: 2.0.0
        `verify` module-level function is replaced by
        `Certificate.verify` method to conform with OOP standards.
    """
    warnings.warn(
        DeprecationWarning(
            "Module-level `verify` function is deprecated. "
            "Use Certificate.verify method instead"
        )
    )
    return cert.verify()
