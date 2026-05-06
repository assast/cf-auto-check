from src.main import CFAutoCheck


class DummyApiClient:
    def __init__(self, cfips=None, error=None):
        self.cfips = list(cfips or [])
        self.error = error
        self.blacklist_calls = []

    def get_cf_ips(self, raise_on_error=False):
        if self.error:
            if raise_on_error:
                raise self.error
            return []
        return list(self.cfips)

    def batch_blacklist_cf_ips(self, ids, sync_blacklisted=True):
        self.blacklist_calls.append((list(ids), sync_blacklisted))
        return {
            'success': True,
            'requested': len(ids),
            'changes': len(ids),
            'sync_blacklisted': 1 if sync_blacklisted else 0
        }


def build_service(api_client, current_ip='134.185.109.244', filter_port=443):
    service = object.__new__(CFAutoCheck)
    service.api_client = api_client
    service.check_running = False
    service.last_check_meta = {}
    service.cf_api_token = 'token'
    service.cf_zone_id = 'zone'
    service.cf_record_name = 'record.example.com'
    service.sync_to_cf_filter_port = filter_port
    service._get_current_cf_dns_ip = lambda: current_ip
    service.trigger_enabled_maintenance = lambda source='api': f'maint:{source}'
    return service


def test_blacklist_current_cf_matches_exact_invalid_record():
    api_client = DummyApiClient(cfips=[
        {
            'id': 15115,
            'address': '134.185.109.244',
            'port': 443,
            'status': 'invalid',
            'sync_blacklisted': 0
        }
    ])
    service = build_service(api_client)

    result, status_code = service.blacklist_current_cf_and_trigger_maintenance(source='api')

    assert status_code == 200
    assert result['blacklisted_ids'] == [15115]
    assert api_client.blacklist_calls == [([15115], True)]


def test_blacklist_current_cf_returns_502_when_cfip_query_fails():
    api_client = DummyApiClient(error=RuntimeError('backend 503'))
    service = build_service(api_client)

    result, status_code = service.blacklist_current_cf_and_trigger_maintenance(source='api')

    assert status_code == 502
    assert result['error'] == 'Failed to query CFIP records'
    assert result['current_ip'] == '134.185.109.244'
