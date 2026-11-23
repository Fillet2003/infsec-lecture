from datetime import datetime, timedelta
import pandas as pd
import numpy as np

class CloudIntegrationModule:
    # Адаптер к облачным провайдерам (AWS CloudWatch / Azure Monitor).

    def __init__(self, analyzer, provider='AWS'):
        self.analyzer = analyzer
        self.provider = provider

    def fetch_logs(self, hours=24):
        # Получить сетевые события из облака (заглушка).
        # В реальности здесь: boto3.client('logs').filter_log_events(...)
        n = 500
        now = datetime.now()
        df = pd.DataFrame({
            'timestamp': [now - timedelta(seconds=i * 60) for i in range(n)],
            'source_ip': [f'10.0.0.{np.random.randint(1, 250)}' for _ in range(n)],
            'destination_ip': [f'52.{np.random.randint(1, 250)}.0.1' for _ in range(n)],
            'protocol': np.random.choice(['HTTPS', 'DNS', 'SSH'], n),
            'port': np.random.choice([443, 53, 22], n),
            'size_bytes': np.random.randint(100, 65535, n),
            'department': ['cloud'] * n,
        })
        self.analyzer.log_audit_event(
            'system', 'CLOUD_FETCH', details=f'{self.provider}: {n} событий')
        print(f'☁️ {self.provider}: получено {n} событий')
        return df

    def sync(self):
        # Подтянуть облачные логи в общий поток анализатора.
        cloud_df = self.fetch_logs()
        self.analyzer.traffic_df = pd.concat(
            [self.analyzer.traffic_df, cloud_df], ignore_index=True
        ).sort_values('timestamp').reset_index(drop=True)
        return cloud_df