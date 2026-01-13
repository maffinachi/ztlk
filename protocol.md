Транспорт: TCP (plain), одна TCP‑сессия = JSON‑сообщения, utf‑8. Каждое сообщение — одна строка, завершается '\n'. Сообщения — JSON‑объекты с полем "type". Пример: {"type":"CHALLENGE","nonce":"..."}

Основные типы сообщений (client → server):

HELLO: {"type":"HELLO","client":"zettel-cli","version":"0.1"}
AUTH: {"type":"AUTH","nick":"","token":"","pubkey":"","sig":""} — sig = sign(nonce, secret_key)
POST_NOTE: {"type":"POST_NOTE","id":"","title":"...","body_b64":"...","parent":"|null","ts":,"sig":"base64"} — note body base64
SUBSCRIBE: {"type":"SUBSCRIBE","thread":"|nick:"} — получаем события NOTE для этой нити
FETCH: {"type":"FETCH","thread":"","since_ts":}
PEER_CONNECT (server->server flow): {"type":"PEER_HELLO","server_name":"...", "version":"0.1"}
PING / PONG

Основные типы сообщений (server → client):

CHALLENGE: {"type":"CHALLENGE","nonce":"..."}
AUTH_OK: {"type":"AUTH_OK","nick":"..."}
AUTH_FAIL: {"type":"AUTH_FAIL","reason":"..."}
NOTE: {"type":"NOTE","id":"...","nick":"...","title":"...","body_b64":"...","parent":"...","ts":...,"sig":"..."}
MANIFEST: {"type":"MANIFEST","nick":"...","notes":[{"id":"...","ts":...},...]}
REQUEST_NOTE: {"type":"REQUEST_NOTE","id":"..."} (peer request)
ERROR: {"type":"ERROR","reason":"..."}

Server ↔ Server (replication):

TCP connection established to peer.
Exchange PEER_HELLO.
Peer A sends MANIFEST for all notes (or since timestamp).
Peer B compares, replies REQUEST_NOTE for missing ones.
Peer A sends NOTE messages for each requested note.
Peers may subscribe to each other's events for live replication.

Подпись и авторизация:

При установлении соединения сервер шлёт CHALLENGE (nonce).
Клиент формирует AUTH с base64(pubkey) и signature = ed25519_sign(nonce, secret_key). Также включает token (строка), выданный TON‑контрактом пользователю.
Сервер проверяет: a) sig валидна для nonce и pubkey (libsodium). b) token валиден для pubkey: verify_token_on_chain(token, pubkey) — точная проверка зависит от контракта; в демо используется локальная формула: token == base64(sha256(pubkey||":"||issue_time)) — в реальном мире заменить RPC/API.

Заметка (NOTE) — подписана автором (sig = sign(serialized_note, secret_key)), сервер сохраняет заметку и реплицирует.
