"""Credential-free smoke test of the actual rmcp stdio server."""
import json
import pathlib
import queue
import shutil
import subprocess
import sys
import tempfile
import threading

root = pathlib.Path(__file__).resolve().parents[1]
binary = pathlib.Path(sys.argv[1]).resolve()
with tempfile.TemporaryDirectory() as directory:
    project = pathlib.Path(directory)
    shutil.copyfile(root / 'tests/fixtures/secrets.toml', project / 'secrets.toml')
    process = subprocess.Popen([str(binary), '--project', str(project)],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                               stderr=subprocess.DEVNULL, text=True)
    messages = queue.Queue()

    def collect():
        for line in process.stdout:
            messages.put(json.loads(line))

    threading.Thread(target=collect, daemon=True).start()

    def send(method, params, request_id=None):
        message = {'jsonrpc': '2.0', 'method': method, 'params': params}
        if request_id is not None:
            message['id'] = request_id
        process.stdin.write(json.dumps(message) + '\n')
        process.stdin.flush()
        if request_id is not None:
            while True:
                reply = messages.get(timeout=30)
                if reply.get('id') == request_id:
                    return reply

    try:
        initialized = send('initialize', {
            'protocolVersion': '2025-11-25', 'capabilities': {},
            'clientInfo': {'name': 'opv-smoke', 'version': '1'}}, 1)
        assert 'result' in initialized, initialized
        send('notifications/initialized', {})
        tools = send('tools/list', {}, 2)['result']['tools']
        assert {tool['name'] for tool in tools} == {
            'opv_ready', 'opv_configuration', 'opv_deployment_plan'}
        assert all(tool['annotations']['readOnlyHint'] for tool in tools)
        reply = send('tools/call', {'name': 'opv_configuration', 'arguments': {}}, 3)
        text = reply['result']['content'][0]['text']
        config = json.loads(text)
        assert config['ok'], config
        assert config['keys'] and config['environments']
        assert all(set(key) == {'product', 'key', 'kind'} for key in config['keys'])
        assert 'vault_id' not in text and 'item_id' not in text and 'rules' not in text
        refused = send('tools/call', {'name': 'opv_sync', 'arguments': {'approved': True}}, 4)
        assert 'error' in refused or refused['result'].get('isError'), refused
        extra = send('tools/call', {'name': 'opv_ready', 'arguments': {
            'environment': 'prod', 'approved': True, 'value': 'SECRET_MARKER'}}, 5)
        assert 'error' in extra or extra['result'].get('isError'), extra
        assert 'SECRET_MARKER' not in json.dumps(extra), extra
        print('PASS: initialize, tools/list, configuration inspection, mutation refusal, and argument rejection')
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
