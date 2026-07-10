from Cryptorix import fernet


def test_roundtrip_dict():
    key = fernet.generate_key()
    payload = {"status": "ok"}
    token = fernet.encrypt(payload, key=key)
    assert fernet.decrypt(token, key=key) == '{"status": "ok"}'


def test_roundtrip_str():
    key = fernet.generate_key()
    token = fernet.encrypt("apples", key=key)
    assert fernet.decrypt(token, key=key) == "apples"
