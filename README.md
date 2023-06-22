EmberTalk Key Server
====================

Retrieve a Challenge
--------------------

`POST /challenge`

Request body:

```json
{"pubkey": [0, 0]
```

(Serialized as byte array)

Response:

```json
{
    "challenge": [1, 2, 3],
    "state": [4, 5, 6],
    "nonce": [7, 8, 9]
}
```

Keep `state` and `nonce`, you need to send them in the response. Decrypt
`challenge` with your private key, this will give you a plaintext (the
challenge response).

Respond to a Challenge
----------------------

`POST /response`

Response body:

```json
{
    "response": [1, 2, 3],
    "state": [4, 5, 6],
    "nonce": [7, 8, 9],
    "name": "guido"
}
```

`response` is the decrypted challenge, `state` and `nonce` should be
transmitted verbatim as they were received, `name` is a freely choosable
identifier (must be unique, case sensitive).

Retrieve a Key
--------------

`GET /keys/:identifier`

Response body:

```json
{"pubkey": [1, 2, 3]}
```
