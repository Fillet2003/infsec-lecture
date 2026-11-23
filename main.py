from NetworkTrafficAnalyser import NetworkTrafficAnalyzer
from BiometryIntegration import BiometricAuthModule
from CloudIntegration import CloudIntegrationModule

def main():
    """
    Главная функция демонстрации системы мониторинга
    """
    print("="*70)
    print("СИСТЕМА МОНИТОРИНГА СЕТЕВОГО ТРАФИКА ПРЕДПРИЯТИЯ")
    print("Учебный кейс для дисциплины 'Обеспечение ИБ бизнес-процессов'")
    print("="*70)

    # Инициализация
    analyzer = NetworkTrafficAnalyzer(company_name="ТехноПрофи")
    scanner = BiometricAuthModule(analyzer=analyzer)

    scanner.authenticate(user_id=123)
    analyzer.cloud.sync()
    analyzer.threat_intel.enrich()

    # Генерация имитационных данных
    traffic_data = analyzer.simulate_traffic_data(hours=24, users=50)
    analyzer.inject_ddos_burst()

    # Анализ трафика
    analyzer.analyze_traffic_patterns()

    # Обнаружение нарушений
    violations = analyzer.detect_policy_violations()
    analyzer.DDoS_analysis()

    # Генерация отчета
    analyzer.generate_security_report()

    # Визуализация
    analyzer.visualize_traffic()

    print("\n" + "="*70)
    print("КЕЙС УСПЕШНО ЗАВЕРШЁН")
    print("="*70)
    
    # Демонстрация первых 5 записей трафика
    print("\nПример записей трафика (первые 5):")
    print(traffic_data.head().to_string())

if __name__ == "__main__":
    main()
