"""
payloads.py — AutheAndAutho Module
"""

IDOR_PARAMS = [
    "id",
    "user",
    "user_id",
    "account",
    "account_id",
    "profile",
    "profile_id",
    "uid",
    "uuid",
    "customer_id",
    "doc_id",
    "order_id",
]

# Valor para testar substituição em IDORs (se vermos id=1, testamos id=IDOR_TEST_VALUE)
IDOR_TEST_VALUE = "999999"

RATE_LIMIT_HEADERS = [
    "x-ratelimit-limit",
    "x-ratelimit-remaining",
    "retry-after",
]
