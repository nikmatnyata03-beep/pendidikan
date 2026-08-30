import asyncio
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives.asymmetric import rsa

from app.config import Settings
from app.identity import IdentityError, OidcVerifier


class StaticJwks:
    def __init__(self, key):
        self.key = key

    async def get(self, kid):
        assert kid == "key-1"
        return self.key


def _settings():
    return Settings(
        environment="test",
        database_url="",
        oidc_issuer="https://sso.example.edu/realms/campus",
        oidc_audience="nexus-campus-api",
        oidc_jwks_url="https://sso.example.edu/certs",
        oidc_algorithms=("RS256",),
        oidc_clock_skew_seconds=0,
        allowed_origins=(),
    )


def test_rsa_oidc_token_is_verified_end_to_end():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": "key-1", "alg": "RS256", "use": "sig"})
    token = jwt.encode(
        {"sub": "student-1", "iss": _settings().oidc_issuer, "aud": _settings().oidc_audience, "exp": int(time.time()) + 60, "name": "Alya"},
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )
    verifier = OidcVerifier(_settings(), jwks=StaticJwks(jwk))

    identity = asyncio.run(verifier.verify(token))

    assert identity.subject == "student-1"
    assert identity.display_name == "Alya"


def test_wrong_audience_is_rejected():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public_key = private_key.public_key()
    jwk = json.loads(jwt.algorithms.RSAAlgorithm.to_jwk(public_key))
    jwk.update({"kid": "key-1", "alg": "RS256", "use": "sig"})
    settings = _settings()
    token = jwt.encode(
        {"sub": "student-1", "iss": settings.oidc_issuer, "aud": "another-api", "exp": int(time.time()) + 60},
        private_key,
        algorithm="RS256",
        headers={"kid": "key-1"},
    )
    verifier = OidcVerifier(settings, jwks=StaticJwks(jwk))

    with pytest.raises(IdentityError):
        asyncio.run(verifier.verify(token))


def test_symmetric_algorithm_configuration_is_rejected():
    settings = _settings()
    bad_settings = Settings(
        environment=settings.environment,
        database_url=settings.database_url,
        oidc_issuer=settings.oidc_issuer,
        oidc_audience=settings.oidc_audience,
        oidc_jwks_url=settings.oidc_jwks_url,
        oidc_algorithms=("HS256",),
        oidc_clock_skew_seconds=settings.oidc_clock_skew_seconds,
        allowed_origins=settings.allowed_origins,
    )

    with pytest.raises(ValueError, match="asymmetric"):
        OidcVerifier(bad_settings, jwks=StaticJwks({}))
