from src.api_client import ApiClient


def test_set_cf_ip_blacklist_fallback_put_uses_only_sync_blacklisted():
    client = ApiClient()
    captured = {}

    def fake_retry(method, endpoint, data=None):
        raise RuntimeError('blacklist endpoint unavailable')

    def fake_update(ip_id, data):
        captured['id'] = ip_id
        captured['data'] = data
        return {'success': True, 'data': {'changes': 1}}

    client._retry_request = fake_retry
    client.update_cf_ip = fake_update

    result = client.set_cf_ip_blacklist(12, blacklisted=True, field_name='sync_blacklisted')

    assert result == {'success': True, 'data': {'changes': 1}}
    assert captured == {'id': 12, 'data': {'sync_blacklisted': 1}}


def test_set_cf_ip_blacklist_fallback_put_uses_only_node_blacklisted():
    client = ApiClient()
    captured = {}

    def fake_retry(method, endpoint, data=None):
        raise RuntimeError('blacklist endpoint unavailable')

    def fake_update(ip_id, data):
        captured['id'] = ip_id
        captured['data'] = data
        return {'success': True, 'data': {'changes': 1}}

    client._retry_request = fake_retry
    client.update_cf_ip = fake_update

    result = client.set_cf_ip_blacklist(34, blacklisted=False, field_name='node_blacklisted')

    assert result == {'success': True, 'data': {'changes': 1}}
    assert captured == {'id': 34, 'data': {'node_blacklisted': 0}}
