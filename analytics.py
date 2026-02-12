"""
Sistema de Analytics - Estatísticas e Métricas em tempo real
"""
import json
from datetime import datetime, timedelta
from collections import defaultdict
import os

DATA_DIR = os.path.join(os.path.dirname(__file__), 'data')


class AnalyticsManager:
    """Gerenciador de analytics e estatísticas"""
    
    def __init__(self):
        self.metrics_file = os.path.join(DATA_DIR, 'metrics.json')
        self.page_views = defaultdict(int)
        self.hourly_connections = defaultdict(int)
        self.daily_connections = defaultdict(int)
        self.geo_data = {}  # IP -> geo info
        self.session_durations = []
        self.events = []
        self._load_data()
    
    def _load_data(self):
        """Carrega métricas salvas"""
        try:
            if os.path.exists(self.metrics_file):
                with open(self.metrics_file, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    self.page_views = defaultdict(int, data.get('page_views', {}))
                    self.hourly_connections = defaultdict(int, data.get('hourly_connections', {}))
                    self.daily_connections = defaultdict(int, data.get('daily_connections', {}))
                    self.geo_data = data.get('geo_data', {})
                    self.session_durations = data.get('session_durations', [])[-1000:]
                    self.events = data.get('events', [])[-500:]
        except Exception as e:
            print(f"[ANALYTICS] Erro ao carregar: {e}")
    
    def _save_data(self):
        """Salva métricas"""
        try:
            os.makedirs(DATA_DIR, exist_ok=True)
            with open(self.metrics_file, 'w', encoding='utf-8') as f:
                json.dump({
                    'page_views': dict(self.page_views),
                    'hourly_connections': dict(self.hourly_connections),
                    'daily_connections': dict(self.daily_connections),
                    'geo_data': self.geo_data,
                    'session_durations': self.session_durations[-1000:],
                    'events': self.events[-500:]
                }, f, ensure_ascii=False, indent=2)
        except Exception as e:
            print(f"[ANALYTICS] Erro ao salvar: {e}")
    
    def track_page_view(self, page: str, ip: str = None):
        """Registra visualização de página"""
        self.page_views[page] += 1
        self._log_event('page_view', {'page': page, 'ip': ip})
    
    def track_connection(self, ip: str):
        """Registra conexão"""
        now = datetime.now()
        hour_key = now.strftime('%Y-%m-%d %H:00')
        day_key = now.strftime('%Y-%m-%d')
        
        self.hourly_connections[hour_key] += 1
        self.daily_connections[day_key] += 1
        self._save_data()
    
    def track_session_duration(self, duration_seconds: int):
        """Registra duração de sessão"""
        self.session_durations.append({
            'duration': duration_seconds,
            'timestamp': datetime.now().isoformat()
        })
        if len(self.session_durations) > 1000:
            self.session_durations = self.session_durations[-1000:]
        self._save_data()
    
    def set_geo_data(self, ip: str, geo_info: dict):
        """Define dados de geolocalização para IP"""
        self.geo_data[ip] = {
            **geo_info,
            'updated_at': datetime.now().isoformat()
        }
        self._save_data()
    
    def _log_event(self, event_type: str, data: dict):
        """Registra evento"""
        self.events.append({
            'type': event_type,
            'data': data,
            'timestamp': datetime.now().isoformat()
        })
        if len(self.events) > 500:
            self.events = self.events[-500:]
    
    def get_dashboard_stats(self) -> dict:
        """Retorna estatísticas para o dashboard"""
        now = datetime.now()
        today = now.strftime('%Y-%m-%d')
        current_hour = now.strftime('%Y-%m-%d %H:00')
        
        # Conexões das últimas 24h
        last_24h = []
        for i in range(24):
            hour = (now - timedelta(hours=i)).strftime('%Y-%m-%d %H:00')
            last_24h.append({
                'hour': hour,
                'count': self.hourly_connections.get(hour, 0)
            })
        
        # Conexões dos últimos 7 dias
        last_7days = []
        for i in range(7):
            day = (now - timedelta(days=i)).strftime('%Y-%m-%d')
            last_7days.append({
                'day': day,
                'count': self.daily_connections.get(day, 0)
            })
        
        # Páginas mais visitadas
        top_pages = sorted(self.page_views.items(), key=lambda x: x[1], reverse=True)[:10]
        
        # Média de duração de sessão
        avg_duration = 0
        if self.session_durations:
            avg_duration = sum(s['duration'] for s in self.session_durations) / len(self.session_durations)
        
        return {
            'today_connections': self.daily_connections.get(today, 0),
            'current_hour_connections': self.hourly_connections.get(current_hour, 0),
            'total_page_views': sum(self.page_views.values()),
            'top_pages': [{'page': p, 'views': v} for p, v in top_pages],
            'hourly_chart': list(reversed(last_24h)),
            'daily_chart': list(reversed(last_7days)),
            'avg_session_duration': round(avg_duration, 2),
            'geo_locations': list(self.geo_data.values()),
            'recent_events': self.events[-20:]
        }
    
    def get_geo_stats(self) -> dict:
        """Retorna estatísticas de geolocalização"""
        countries = defaultdict(int)
        cities = defaultdict(int)
        
        for ip, geo in self.geo_data.items():
            if geo.get('country'):
                countries[geo['country']] += 1
            if geo.get('city'):
                cities[geo['city']] += 1
        
        return {
            'countries': dict(countries),
            'cities': dict(cities),
            'total_locations': len(self.geo_data)
        }


# Instância global
analytics = AnalyticsManager()


def get_ip_geolocation_sync(ip: str) -> dict:
    """Versão síncrona da geolocalização"""
    import requests
    
    try:
        resp = requests.get(f'http://ip-api.com/json/{ip}', timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            if data.get('status') == 'success':
                return {
                    'ip': ip,
                    'country': data.get('country', 'Desconhecido'),
                    'country_code': data.get('countryCode', ''),
                    'region': data.get('regionName', ''),
                    'city': data.get('city', ''),
                    'lat': data.get('lat', 0),
                    'lon': data.get('lon', 0),
                    'isp': data.get('isp', ''),
                    'org': data.get('org', ''),
                    'timezone': data.get('timezone', '')
                }
    except Exception as e:
        print(f"[GEO] Erro ao obter localização: {e}")
    
    return {'ip': ip, 'country': 'Desconhecido', 'city': '', 'lat': 0, 'lon': 0}
