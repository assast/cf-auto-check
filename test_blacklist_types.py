from src.main import CFAutoCheck


def build_service():
    service = object.__new__(CFAutoCheck)
    service.ip_port_to_cfips = {}
    service.sync_to_cf_filter_port = 443
    return service


class DummyApiClient:
    def __init__(self, cfips=None):
        self.cfips = list(cfips or [])
        self.blacklist_calls = []

    def get_cf_ips(self, raise_on_error=False):
        return list(self.cfips)

    def batch_blacklist_cf_ips(self, ids, blacklisted=True, field_name='sync_blacklisted'):
        self.blacklist_calls.append((list(ids), blacklisted, field_name))
        return {
            'success': True,
            'requested': len(ids),
            'changes': len(ids),
            'blacklist_type': 'dns' if field_name == 'sync_blacklisted' else 'node',
            'blacklist_field': field_name,
            field_name: 1 if blacklisted else 0
        }


def test_filter_node_allowed_cfips_keeps_sync_blacklisted_records():
    service = build_service()
    cfips = [
        {'id': 1, 'address': '1.1.1.1', 'port': 443, 'sync_blacklisted': 1},
        {'id': 2, 'address': '2.2.2.2', 'port': 443, 'node_blacklisted': 1},
        {'id': 3, 'address': '3.3.3.3', 'port': 443, 'node_blacklisted': 0},
    ]

    allowed = service._filter_node_allowed_cfips(cfips, "Test")

    assert [item['id'] for item in allowed] == [1, 3]


def test_select_enabled_maintenance_cfips_filters_node_blacklist_only():
    service = build_service()
    cfips = [
        {'id': 1, 'status': 'enabled', 'sync_blacklisted': 1},
        {'id': 2, 'status': 'enabled', 'node_blacklisted': 1},
        {'id': 3, 'status': 'disabled', 'node_blacklisted': 0},
    ]

    enabled_cfips, skipped = service._select_enabled_maintenance_cfips(cfips)

    assert [item['id'] for item in enabled_cfips] == [1]
    assert skipped == 1


def test_filter_dns_sync_candidates_skips_sync_blacklisted_results():
    service = build_service()
    service.ip_port_to_cfips = {
        ('1.1.1.1', 443): [{'id': 1, 'sync_blacklisted': 1}],
        ('2.2.2.2', 443): [{'id': 2, 'sync_blacklisted': 0}],
    }
    results = [
        {'address': '1.1.1.1', 'port': 443, 'speed': 10, 'latency': 5},
        {'address': '2.2.2.2', 'port': 443, 'speed': 8, 'latency': 6},
    ]

    allowed, skipped = service._filter_dns_sync_candidates(results, "[Test]")

    assert skipped == 1
    assert [item['address'] for item in allowed] == ['2.2.2.2']


def test_filter_dns_sync_candidates_skips_duplicate_when_any_record_blacklisted():
    service = build_service()
    service.ip_port_to_cfips = {
        ('1.1.1.1', 443): [
            {'id': 1, 'sync_blacklisted': 1},
            {'id': 2, 'sync_blacklisted': 0},
        ],
        ('2.2.2.2', 443): [{'id': 3, 'sync_blacklisted': 0}],
    }
    results = [
        {'address': '1.1.1.1', 'port': 443, 'speed': 10, 'latency': 5},
        {'address': '2.2.2.2', 'port': 443, 'speed': 8, 'latency': 6},
    ]

    allowed, skipped = service._filter_dns_sync_candidates(results, "[Test]")

    assert skipped == 1
    assert [item['address'] for item in allowed] == ['2.2.2.2']


def test_filter_dns_sync_candidates_matches_string_port_blacklist_mapping():
    service = build_service()
    service.ip_port_to_cfips = {
        ('1.1.1.1', '443'): [{'id': 1, 'sync_blacklisted': 1}],
        ('2.2.2.2', 443): [{'id': 2, 'sync_blacklisted': 0}],
    }
    results = [
        {'address': '1.1.1.1', 'port': 443, 'speed': 10, 'latency': 5},
        {'address': '2.2.2.2', 'port': 443, 'speed': 8, 'latency': 6},
    ]

    allowed, skipped = service._filter_dns_sync_candidates(results, "[Test]")

    assert skipped == 1
    assert [item['address'] for item in allowed] == ['2.2.2.2']


def test_filter_dns_sync_candidates_skips_unmapped_results():
    service = build_service()
    service.ip_port_to_cfips = {
        ('2.2.2.2', 443): [{'id': 2, 'sync_blacklisted': 0}],
    }
    results = [
        {'address': '1.1.1.1', 'port': 443, 'speed': 10, 'latency': 5},
        {'address': '2.2.2.2', 'port': 443, 'speed': 8, 'latency': 6},
    ]

    allowed, skipped = service._filter_dns_sync_candidates(results, "[Test]")

    assert skipped == 1
    assert [item['address'] for item in allowed] == ['2.2.2.2']


def test_query_cfip_blacklist_records_filters_node_blacklisted_entries():
    service = build_service()
    service.api_client = DummyApiClient(cfips=[
        {'id': 1, 'address': '1.1.1.1', 'port': 443, 'status': 'enabled', 'sync_blacklisted': 1, 'node_blacklisted': 0},
        {'id': 2, 'address': '2.2.2.2', 'port': 8443, 'status': 'disabled', 'sync_blacklisted': 0, 'node_blacklisted': 1},
        {'id': 3, 'address': '3.3.3.3', 'port': 443, 'status': 'enabled', 'sync_blacklisted': 0, 'node_blacklisted': 0},
    ])

    result, status_code = service.query_cfip_blacklist_records(
        blacklist_type='node',
        blacklisted='true'
    )

    assert status_code == 200
    assert result['field_name'] == 'node_blacklisted'
    assert result['count'] == 1
    assert result['items'][0]['id'] == 2
    assert result['items'][0]['node_blacklisted'] == 1


def test_set_cfip_blacklist_records_supports_node_unblacklist():
    api_client = DummyApiClient()
    service = build_service()
    service.api_client = api_client

    result, status_code = service.set_cfip_blacklist_records(
        blacklist_type='node',
        ids=['2', '3'],
        blacklisted='false'
    )

    assert status_code == 200
    assert result['blacklist_type'] == 'node'
    assert result['field_name'] == 'node_blacklisted'
    assert result['blacklisted'] is False
    assert api_client.blacklist_calls == [([2, 3], False, 'node_blacklisted')]
