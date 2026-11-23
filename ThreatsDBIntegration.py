import requests

class ThreatIntelModule:
    # Адаптер к базам данных угроз (MISP / AlienVault OTX).
    def __init__(self, analyzer):
        self.analyzer = analyzer
        self.misp_url = None       # 'https://misp.local'
        self.misp_key = None       # 'AUTH_KEY'
        self.otx_key = None        # 'X-OTX-API-KEY'

    def _query_misp(self, ip):
        # Реальный запрос к MISP: ищем IP в атрибутах.
        if not (self.misp_url and self.misp_key):
            return []  # в лабе ключей нет — сразу пусто
        try:
            r = requests.post(
                f'{self.misp_url}/attributes/restSearch',
                headers={'Authorization': self.misp_key,
                         'Accept': 'application/json'},
                json={'returnFormat': 'json', 'value': ip, 'type': 'ip-dst'},
                timeout=5,
            )
            return r.json().get('response', {}).get('Attribute', [])
        except requests.RequestException:
            return []

    def _query_otx(self, ip):
        # Реальный запрос к OTX: pulse_info.count > 0 = грязный IP.
        if not self.otx_key:
            return 0
        try:
            r = requests.get(
                f'https://otx.alienvault.com/api/v1/indicators/IPv4/{ip}/general',
                headers={'X-OTX-API-KEY': self.otx_key},
                timeout=5,
            )
            return r.json().get('pulse_info', {}).get('count', 0)
        except requests.RequestException:
            return 0

    def check_ip(self, ip):
        # Проверка одного IP по обеим базам. Возвращает True, если «грязный».
        misp_hits = self._query_misp(ip)
        otx_hits = self._query_otx(ip)
        dirty = bool(misp_hits) or otx_hits > 0

        if dirty:
            details = f'MISP: {len(misp_hits)}, OTX: {otx_hits} pulses'
            self.analyzer.log_audit_event(
                'system', 'THREAT_INTEL_HIT', details=f'{ip}: {details}')
            self.analyzer.send_alert(
                f'IP {ip} в базах угроз ({details})', level='HIGH')
        return dirty

    def enrich(self, limit=50):
        # Проверить первые N уникальных source_ip из traffic_df.
        ips = self.analyzer.traffic_df['source_ip'].unique()[:limit]
        dirty_ips = [ip for ip in ips if self.check_ip(ip)]
        print(f'🛡️ Threat Intel: {len(dirty_ips)} из {len(ips)} IP «грязные»')
        return dirty_ips