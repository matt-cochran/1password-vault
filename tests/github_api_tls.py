"""Actual gh HTTPS transport + Rust backend + pinned action consumer, no accounts.

Usage: python3 tests/github_api_tls.py PROBE_BINARY PINNED_ACTION_CHECKOUT
Requires Python cryptography, system libsodium, gh and Node >=24. The checkout
must be actions/create-github-app-token@bcd2ba49218906704ab6c1aa796996da409d3eb1
with its unmodified package-lock.json and npm ci --omit=dev --ignore-scripts.
Only an unrelated TLS fixture key is written to a file. Payloads stay in memory.
"""
import base64
import ctypes
import ctypes.util
import datetime
import http.server
import ipaddress
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import threading
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

probe, action = (Path(p).resolve() for p in sys.argv[1:])
assert subprocess.check_output(['git', '-C', str(action), 'rev-parse', 'HEAD'], text=True).strip() == 'bcd2ba49218906704ab6c1aa796996da409d3eb1'
assert subprocess.run(['git', '-C', str(action), 'diff', '--exit-code', '--', 'package.json', 'package-lock.json', 'main.js'], capture_output=True).returncode == 0
lock = json.loads((action / 'package-lock.json').read_text())
assert lock['packages']['node_modules/@octokit/auth-app']['version'] == '8.2.0'
sodium = ctypes.CDLL(ctypes.util.find_library('sodium'))
assert sodium.sodium_init() >= 0
pk, sk = ctypes.create_string_buffer(32), ctypes.create_string_buffer(32)
assert sodium.crypto_box_keypair(pk, sk) == 0
seen, requests, errors = [], [], []
class Handler(http.server.BaseHTTPRequestHandler):
    def log_message(self, *_):
        pass
    def do_GET(self):
        requests.append(('GET', self.path))
        if self.path != '/api/v3/repos/example/app/environments/fixture/secrets/public-key':
            self.send_error(404); return
        body = json.dumps({'key_id': 'fixture-key', 'key': base64.b64encode(pk.raw).decode()}).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(body)
    def do_PUT(self):
        requests.append(('PUT', self.path))
        if self.path != '/api/v3/repos/example/app/environments/fixture/secrets/FIXTURE_APP_KEY':
            self.send_error(404); return
        try:
            if self.headers.get('Transfer-Encoding') == 'chunked':
                chunks = []
                while True:
                    size = int(self.rfile.readline().strip(), 16)
                    assert 0 <= size <= 100_000
                    if not size:
                        assert self.rfile.readline() == b'\r\n'
                        break
                    chunks.append(self.rfile.read(size))
                    assert self.rfile.read(2) == b'\r\n'
                body = b''.join(chunks)
            else:
                body = self.rfile.read(int(self.headers['Content-Length']))
            assert len(body) <= 100_000
            data = json.loads(body)
            assert set(data) == {'key_id', 'encrypted_value'} and data['key_id'] == 'fixture-key'
            cipher = base64.b64decode(data['encrypted_value'], validate=True)
            plain = ctypes.create_string_buffer(len(cipher) - 48)
            assert sodium.crypto_box_seal_open(plain, cipher, len(cipher), pk, sk) == 0
            assert plain.raw not in body
            seen.append(plain.raw)
            self.send_response(201); self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(b'{}')
        except Exception:
            errors.append('invalid encrypted payload')
            self.send_error(400)

with tempfile.TemporaryDirectory(prefix='opv-api-tls-') as directory:
    root = Path(directory)
    tls_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, '127.0.0.1')])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(subject).public_key(tls_key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - datetime.timedelta(minutes=1))
            .not_valid_after(now + datetime.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.IPAddress(ipaddress.ip_address('127.0.0.1'))]), False)
            .sign(tls_key, hashes.SHA256()))
    (root/'tls.key').write_bytes(tls_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    (root/'tls.key').chmod(0o600)
    (root/'ca.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (root/'home').mkdir()
    server = http.server.HTTPServer(('127.0.0.1', 0), Handler)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(root/'ca.pem', root/'tls.key')
    server.socket = context.wrap_socket(server.socket, server_side=True)
    thread = threading.Thread(target=server.serve_forever, daemon=True); thread.start()
    env = {'PATH': os.environ['PATH'], 'HOME': str(root/'home'), 'GH_CONFIG_DIR': str(root/'home'),
           'GH_HOST': '127.0.0.1:' + str(server.server_port), 'GH_ENTERPRISE_TOKEN': 'ghp_INVALID_DISPOSABLE_FIXTURE',
           'SSL_CERT_FILE': str(root/'ca.pem'), 'GH_PROMPT_DISABLED': '1', 'GH_NO_UPDATE_NOTIFIER': '1'}
    app_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    payloads = [app_key.private_bytes(serialization.Encoding.PEM, fmt, serialization.NoEncryption())
                for fmt in [serialization.PrivateFormat.TraditionalOpenSSL, serialization.PrivateFormat.PKCS8]]
    payloads.append('{"text":"λ $NAME \\n"}\r\n\r\n'.encode())
    try:
        for payload in payloads:
            result = subprocess.run([str(probe)], input=payload, env=env, capture_output=True, timeout=40)
            assert result.returncode == 0, 'backend fixture failed (output suppressed)'
            assert payload not in result.stdout + result.stderr, 'plaintext output leak'
            assert seen[-1] == payload, 'decrypted bytes differ'
            for path in root.rglob('*'):
                if path.is_file():
                    assert payload not in path.read_bytes(), 'plaintext payload file leak'
        assert not errors and len(seen) == 3 and len(requests) == 6
        # Match the pinned action's exact auth-app dependency. JWT creation is offline;
        # a request callback refuses any attempt to contact GitHub.
        module = (action/'node_modules/@octokit/auth-app/dist-node/index.js').as_uri()
        core = (action/'node_modules/@actions/core/lib/core.js').as_uri()
        node_script = '''import {createPublicKey,verify} from 'node:crypto';
import {createAppAuth} from MODULE;
import * as core from CORE;
let raw=''; for await (const c of process.stdin) raw+=c;
const input=JSON.parse(raw); const key=Buffer.from(input.key,'base64').toString();
process.env['INPUT_PRIVATE-KEY']=key;
const auth=createAppAuth({appId:'123456',privateKey:core.getInput('private-key'),request:()=>{throw Error('network forbidden')}});
const jwt=(await auth({type:'app'})).token; const p=jwt.split('.');
if(String(JSON.parse(Buffer.from(p[1],'base64url')).iss)!=='123456'||!verify('RSA-SHA256',Buffer.from(p[0]+'.'+p[1]),createPublicKey(input.public),Buffer.from(p[2],'base64url'))) throw Error('JWT fixture failed');
'''.replace('MODULE', json.dumps(module)).replace('CORE', json.dumps(core))
        public = app_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
        for payload in seen[:2]:
            result = subprocess.run(['node', '--input-type=module', '-e', node_script],
                input=json.dumps({'key': base64.b64encode(payload).decode(), 'public': public}).encode(),
                env={'PATH': os.environ['PATH'], 'HOME': str(root/'home')}, capture_output=True, timeout=20)
            assert result.returncode == 0, 'pinned action consumer rejected recovered RSA key (output suppressed)'
            assert payload not in result.stdout + result.stderr
        # A refusal is also value-free: an unsupported NUL never reaches HTTPS.
        before = len(requests)
        result = subprocess.run([str(probe)], input=b'DISPOSABLE_NUL_SECRET\0\n', env=env, capture_output=True, timeout=20)
        assert result.returncode != 0 and len(requests) == before
        assert b'DISPOSABLE_NUL_SECRET' not in result.stdout + result.stderr
    finally:
        server.shutdown(); server.server_close(); thread.join()
print('PASS: real HTTPS sealed payloads, exact PEM/UTF-8 CRLF bytes, offline pinned RSA JWT consumer, refusal redaction')
