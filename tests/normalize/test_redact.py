from __future__ import annotations

from kiyooo.normalize.redact import redact_content, redact_text


def test_aws_access_key_is_redacted() -> None:
    text = "found key AKIAABCDEFGHIJKLMNOP in the config"
    redacted, found = redact_text(text)
    assert "AKIAABCDEFGHIJKLMNOP" not in redacted
    assert "[REDACTED:aws_access_key_id:" in redacted
    assert len(found) == 1
    assert found[0].secret_type == "aws_access_key_id"


def test_github_token_is_redacted() -> None:
    token = "ghp_" + "a" * 36
    redacted, found = redact_text(f"Authorization: Bearer {token}")
    assert token not in redacted
    assert found[0].secret_type == "github_token"


def test_slack_token_is_redacted() -> None:
    token = "xoxb-" + "1234567890"
    redacted, found = redact_text(f"slack_token = {token}")
    assert token not in redacted
    assert found[0].secret_type == "slack_token"


def test_private_key_block_is_redacted() -> None:
    text = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA...\n-----END RSA PRIVATE KEY-----"
    redacted, found = redact_text(text)
    assert "MIIEpAIBAAKCAQEA" not in redacted
    assert found[0].secret_type == "private_key_block"


def test_jwt_is_redacted() -> None:
    jwt = (
        "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0."
        "dozjgNryP4J3jVmNHl0w5N_XgL0n3I9PlFUP0THsR8U"
    )
    redacted, found = redact_text(f"token={jwt}")
    assert jwt not in redacted
    assert found[0].secret_type == "jwt"


def test_generic_secret_assignment_is_redacted() -> None:
    redacted, found = redact_text('password: "SuperSecretValue1234"')
    assert "SuperSecretValue1234" not in redacted
    assert found[0].secret_type == "generic_secret_assignment"


def test_ordinary_text_is_left_alone() -> None:
    text = "HTTP 200 OK, server nginx/1.25.0, no secrets here"
    redacted, found = redact_text(text)
    assert redacted == text
    assert found == []


def test_partial_hash_is_deterministic_and_never_the_raw_value() -> None:
    key = "AKIAABCDEFGHIJKLMNOP"
    _, found_a = redact_text(key)
    _, found_b = redact_text(key)
    assert found_a[0].partial_hash == found_b[0].partial_hash
    assert found_a[0].partial_hash != key
    assert len(found_a[0].partial_hash) < len(key)


def test_redact_content_walks_nested_dicts_and_lists() -> None:
    content = {
        "headers": {"Authorization": "Bearer ghp_" + "b" * 36},
        "cookies": ["session=abc", "AKIAABCDEFGHIJKLMNOP"],
        "status_code": 200,
    }
    redacted, found = redact_content(content)
    assert "ghp_" not in str(redacted["headers"])
    assert "AKIAABCDEFGHIJKLMNOP" not in redacted["cookies"][1]
    assert redacted["status_code"] == 200  # non-string values pass through untouched
    assert len(found) == 2


def test_redact_content_empty_dict_returns_no_hits() -> None:
    redacted, found = redact_content({})
    assert redacted == {}
    assert found == []
