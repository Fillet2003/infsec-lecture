import random

class BiometricAuthModule:
    """Адаптер к внешней системе биометрической аутентификации.

    В реальности provider — это SDK сканера (FIDO2/WebAuthn, Face ID,
    отпечаток). Здесь — заглушка, возвращающая score 0..1.
    """
    def __init__(self, analyzer, threshold=0.85):
        self.analyzer = analyzer
        self.threshold = threshold

    def _mock_scan(self, user_id):
        """Имитация сканирования: степень совпадения 0..1."""
        return random.uniform(0, 1)

    def authenticate(self, user_id):
        score = self._mock_scan(user_id)
        ok = score >= self.threshold
        result = 'SUCCESS' if ok else 'DENIED'

        # запись в журнал аудита
        self.analyzer.log_audit_event(
            user=user_id, action='BIOMETRIC_AUTH',
            result=result, details=f'score={score:.2f}')

        # оповещение при отказе
        if not ok:
            self.analyzer.send_alert(
                f'Биометрия не пройдена: {user_id} (score={score:.2f})',
                level='WARNING')
        return ok