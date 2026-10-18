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
# The contract and its sibling bindings: since 0.12.0 ids live only in the bindings file (D-G),
# so the project has to carry both or every command that resolves a boundary fails config_invalid.
fixtures = root / 'tests/fixtures/mcp'
with tempfile.TemporaryDirectory() as directory:
    project = pathlib.Path(directory)
    shutil.copyfile(fixtures / 'secrets.toml', project / 'secrets.toml')
    shutil.copyfile(fixtures / 'secrets.bindings.toml', project / 'secrets.bindings.toml')
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
            'opv_structure_plan', 'opv_delivery_preview', 'opv_changed',
            'opv_propose', 'opv_import_local', 'opv_explain'}
        # The inspection tools, the plans, the proposals and the explanation are read-only;
        # only opv_import_local writes (a local-tier environment's 1Password items). No tool
        # applies structure or syncs: a person runs opv apply or opv sync (design §25.3).
        writers = {'opv_import_local'}
        assert all(tool['annotations']['readOnlyHint'] for tool in tools
                   if tool['name'] not in writers)
        assert not any(tool['annotations'].get('readOnlyHint') for tool in tools
                       if tool['name'] in writers)
        # No tool can remove anything.
        assert not {tool['name'] for tool in tools
                    if tool['annotations'].get('destructiveHint')}
        for tool in tools:
            props = set(tool.get('inputSchema', {}).get('properties', {}) or {})
            assert not props & {'value', 'secret', 'password', 'token', 'approved'}, tool
        # The deployment plan takes the scope a person's opv sync --expect-plan runs.
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
        # An agent cannot sync: there is no sync tool.
        refused = send('tools/call', {'name': 'opv_sync', 'arguments': {
            'environment': 'prod', 'plan_id': '00000000'}}, 4)
        assert 'error' in refused or refused['result'].get('isError'), refused
        extra = send('tools/call', {'name': 'opv_ready', 'arguments': {
            'environment': 'prod', 'approved': True, 'value': 'SECRET_MARKER'}}, 5)
        assert 'error' in extra or extra['result'].get('isError'), extra
        assert 'SECRET_MARKER' not in json.dumps(extra), extra
        # An agent cannot apply structure: there is no apply tool.
        self_applied = send('tools/call', {'name': 'opv_structure_apply', 'arguments': {
            'plan_id': 'sp-0000000000000000'}}, 6)
        assert 'error' in self_applied or self_applied['result'].get('isError'), self_applied
        # A name that is not one is refused before any read.
        refused_plan = send('tools/call', {'name': 'opv_deployment_plan', 'arguments': {
            'environment': 'not a name'}}, 7)
        result = json.loads(refused_plan['result']['content'][0]['text'])
        assert result['ok'] is False, result
        # A failure is the --json document's error object: cause, steps and who acts.
        error = result['error']
        assert {'code', 'category', 'message', 'subject', 'evidence', 'retry',
                'human_required', 'do', 'next'} <= set(error), error
        assert set(error['next']) == {'kind', 'actor', 'command'}, error
        assert isinstance(error['human_required'], bool), error
        # Every 0.11.0 read tool takes the CLI's verbose flag; the 0.12.0 tools take the
        # surface golden's inputs (tests/e2e/expected/surface.json).
        new_tools = {'opv_propose', 'opv_import_local', 'opv_explain'}
        assert all('verbose' in (tool.get('inputSchema', {}).get('properties') or {})
                   for tool in tools if tool['name'] not in new_tools), tools
        # opv_propose advertises the intent document: one arm per kind, no rule parameter.
        propose_tool = next(t for t in tools if t['name'] == 'opv_propose')
        assert len(propose_tool['inputSchema']['oneOf']) == 8, propose_tool
        for arm in propose_tool['inputSchema']['oneOf']:
            assert not set(arm['properties']) & {'value', 'regex', 'rule', 'rules', 'prefix'}, arm
        # The removed write tools are gone, with no alias.
        for removed, request_id in (('opv_declare_key', 8), ('opv_declare_environment', 9),
                                    ('opv_declare_target', 10), ('opv_generate', 11)):
            reply = send('tools/call', {'name': removed, 'arguments': {}}, request_id)
            assert 'error' in reply or reply['result'].get('isError'), reply
        contract = (project / 'secrets.toml').read_text()
        # A value cannot be proposed: the field is refused, naming itself, never the value.
        with_value = send('tools/call', {'name': 'opv_propose', 'arguments': {
            'kind': 'key', 'key': 'NEW_KEY', 'value': 'SECRET_MARKER'}}, 12)
        answer = json.loads(with_value['result']['content'][0]['text'])
        assert answer['ok'] is False, answer
        assert answer['error']['subject']['field'] == ['value'], answer
        assert 'SECRET_MARKER' not in json.dumps(with_value), with_value
        # Nor a rule parameter.
        with_regex = send('tools/call', {'name': 'opv_propose', 'arguments': {
            'kind': 'key', 'key': 'NEW_KEY', 'regex': '^sk_'}}, 13)
        answer = json.loads(with_regex['result']['content'][0]['text'])
        assert answer['error']['subject']['field'] == ['regex'], answer
        # A proposal returns the contract diff and a plan_id, and writes nothing.
        proposed = send('tools/call', {'name': 'opv_propose', 'arguments': {
            'kind': 'key', 'key': 'NEW_KEY', 'product': 'allumata', 'field_kind': 'secret'}}, 14)
        answer = json.loads(proposed['result']['content'][0]['text'])
        assert answer['ok'] is True and answer['plan_id'] and 'NEW_KEY' in answer['diff'], answer
        assert (project / 'secrets.toml').read_text() == contract
        # opv_explain answers the key with names only.
        explained = send('tools/call', {'name': 'opv_explain', 'arguments': {'key': 'NOT_A_KEY'}}, 15)
        answer = json.loads(explained['result']['content'][0]['text'])
        assert answer['ok'] is False and answer['error']['code'], answer
        print('PASS: initialize, tools/list, configuration inspection, proposal purity, value and rule refusal, removed tools, and structural apply refusal')
    finally:
        process.stdin.close()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait()
