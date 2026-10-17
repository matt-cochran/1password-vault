"""Credential-free smoke test of the actual rmcp stdio server (`opv mcp serve`)."""
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
    process = subprocess.Popen([str(binary), 'mcp', 'serve', '--project', str(project)],
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
            'opv_ready', 'opv_configuration', 'opv_deployment_plan', 'opv_access',
            'opv_structure_plan', 'opv_structure_apply', 'opv_declare_key',
            'opv_declare_environment', 'opv_declare_target', 'opv_generate', 'opv_sync',
            'opv_delivery_preview', 'opv_changed'}
        # The inspection tools, the plans and the delivery preview are read-only;
        # declarations edit the local file, generate fills empty 1Password fields, and
        # structure apply and sync need a person's terminal approval.
        writers = {'opv_structure_apply', 'opv_declare_key', 'opv_declare_environment',
                   'opv_declare_target', 'opv_generate', 'opv_sync'}
        assert all(tool['annotations']['readOnlyHint'] for tool in tools
                   if tool['name'] not in writers)
        assert not any(tool['annotations'].get('readOnlyHint') for tool in tools
                       if tool['name'] in writers)
        # Only an approved sync can remove anything (an approved --prune), and says so.
        assert {tool['name'] for tool in tools
                if tool['annotations'].get('destructiveHint')} == {'opv_sync'}
        for tool in tools:
            props = set(tool.get('inputSchema', {}).get('properties', {}) or {})
            assert not props & {'value', 'secret', 'password', 'token', 'approved'}, tool
        apply_tool = next(t for t in tools if t['name'] == 'opv_structure_apply')
        assert set(apply_tool['inputSchema']['properties']) == {'plan_id', 'verbose'}, apply_tool
        sync_tool = next(t for t in tools if t['name'] == 'opv_sync')
        assert set(sync_tool['inputSchema']['properties']) == {
            'environment', 'plan_id', 'targets', 'product', 'deploy', 'prune', 'rotate',
            'verbose'}, sync_tool
        # The deployment plan takes the scope opv_sync approves, so a scoped sync is not stale.
        plan_tool = next(t for t in tools if t['name'] == 'opv_deployment_plan')
        assert set(plan_tool['inputSchema']['properties']) == {
            'environment', 'targets', 'product', 'rotate', 'verbose'}, plan_tool
        reply = send('tools/call', {'name': 'opv_configuration', 'arguments': {}}, 3)
        text = reply['result']['content'][0]['text']
        config = json.loads(text)
        assert config['ok'], config
        assert config['keys'] and config['environments']
        assert all(set(key) == {'product', 'key', 'kind'} for key in config['keys'])
        assert all(set(t) == {'environment', 'name', 'provider', 'products',
                              'state_vault_recorded', 'deploy_credentials_declared'}
                   for t in config['targets']), config['targets']
        assert 'vault_id' not in text and 'item_id' not in text and 'rules' not in text
        # An agent cannot approve its own sync: no approval argument exists, and a plan id
        # nobody approved is refused before any target is touched.
        refused = send('tools/call', {'name': 'opv_sync', 'arguments': {
            'environment': 'prod', 'plan_id': '00000000', 'approved': True}}, 4)
        assert 'error' in refused or refused['result'].get('isError'), refused
        extra = send('tools/call', {'name': 'opv_ready', 'arguments': {
            'environment': 'prod', 'approved': True, 'value': 'SECRET_MARKER'}}, 5)
        assert 'error' in extra or extra['result'].get('isError'), extra
        assert 'SECRET_MARKER' not in json.dumps(extra), extra
        # An agent cannot authorize itself: no approval argument exists, and an unapproved
        # plan id is refused without any write.
        self_approved = send('tools/call', {'name': 'opv_structure_apply', 'arguments': {
            'plan_id': 'sp-0000000000000000', 'approved': True}}, 6)
        assert 'error' in self_approved or self_approved['result'].get('isError'), self_approved
        unapproved = send('tools/call', {'name': 'opv_structure_apply', 'arguments': {
            'plan_id': 'sp-0000000000000000'}}, 7)
        result = json.loads(unapproved['result']['content'][0]['text'])
        assert result['ok'] is False, result
        # A failure is the --json document's error object: cause, steps and who acts.
        error = result['error']
        assert {'code', 'category', 'message', 'subject', 'evidence', 'retry',
                'human_required', 'do', 'next', 'next_kind'} <= set(error), error
        assert isinstance(error['human_required'], bool), error
        # Every tool takes the CLI's verbose flag.
        assert all('verbose' in (tool.get('inputSchema', {}).get('properties') or {})
                   for tool in tools), tools
        # A value cannot be declared: there is no field for it.
        with_value = send('tools/call', {'name': 'opv_declare_key', 'arguments': {
            'product': 'api', 'key': 'NEW_KEY', 'kind': 'secret', 'value': 'SECRET_MARKER'}}, 8)
        assert 'error' in with_value or with_value['result'].get('isError'), with_value
        assert 'SECRET_MARKER' not in (project / 'secrets.toml').read_text()
        print('PASS: initialize, tools/list, configuration inspection, mutation refusal, argument rejection, and structural apply refusal')
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
