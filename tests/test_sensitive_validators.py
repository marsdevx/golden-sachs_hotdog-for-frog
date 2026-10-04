from firewall_app.controls.sensitive_validators import entropy, iban, luhn, pesel_checksum

RANDOM_KEY = "q8ZfK2mXv9LpR4tWb7NcY1hJ3sDgA6eUoP0iTzQx"  # 40 chars, base64 alphabet
GIT_SHA = "3f786850e387550fdab836ed7e6dc881de23001b"


def test_luhn():
    assert luhn("4111 1111 1111 1111")
    assert not luhn("4111 1111 1111 1112")
    assert luhn("4111-1111-1111-1111")
    assert luhn("４１１１１１１１１１１１１１１１")
    assert not luhn("411111111111")


def test_iban():
    assert iban("DE89 3704 0044 0532 0130 00")
    assert not iban("DE89 3704 0044 0532 0130 01")


def test_pesel_checksum():
    assert pesel_checksum("44051401359")
    assert not pesel_checksum("44051401358")


def test_entropy():
    assert len(RANDOM_KEY) == 40 and entropy(RANDOM_KEY)
    assert not entropy("a" * 40)
    assert not entropy(GIT_SHA)
    assert not entropy("")
