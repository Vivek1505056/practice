class SSHEvent:
    def __init__(self, src_ip: str, username: str, threat_score: int, country: str) -> None:
        self.src_ip = src_ip
        self.username = username
        self.threat_score = threat_score
        self.country = country

    def to_dict(self) -> dict:
        return {'src_ip': self.src_ip, 'username': self.username, 'threat_score': self.threat_score, 'country': self.country}
    
    def is_high_risk(self) -> bool:
        if self.threat_score >= 75:
            return True
        return False
    
    @staticmethod 
    def from_dict(data: dict) -> "SSHEvent":
        return SSHEvent(data.get('src_ip'), data.get('username'), data.get('threat_score'), data.get('country'))
    

class SSHEventProcessor:
    def __init__(self, min_threat_score: int):
        self._min_threat_score = min_threat_score
        self._events: list = []
        
    def add_event(self, event: SSHEvent) -> None:
        self._events.append(event)
    
    def get_high_risk(self) -> list:
        high_list = []
        for events in self._events:
            if events.threat_score >= self._min_threat_score:
                high_list.append(events.to_dict())

        return high_list

processor = SSHEventProcessor(min_threat_score=75)
processor.add_event(SSHEvent(src_ip="91.108.56.142", username="admin", threat_score=95, country="Netherlands"))
processor.add_event(SSHEvent(src_ip="1.2.3.4", username="root", threat_score=30, country="Germany")) 
processor.add_event(SSHEvent(src_ip="185.220.101.5", username="guest", threat_score=80, country="Russia"))
print(processor.get_high_risk())