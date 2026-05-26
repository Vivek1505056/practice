# Parser Functions

def parse_ssh(logline: str, metadata: dict) -> dict | None:
    if not metadata.get('src_ip'):
        return None
    else:
        return {**metadata, 'protocol': "SSH", 'logline': logline}
    
def parse_ftp(logline: str, metadata: dict) -> dict | None:
    if not metadata.get('src_ip') or not metadata.get('username'):
        return None
    else:
        return {**metadata, 'protocol': "FTP", 'logline': logline}
    
def parse_http(logline: str, metadata: dict) -> dict | None:
    if not metadata.get('src_ip') or not isinstance(metadata.get('status_code'), int):
        return None
    else:
        return {**metadata, 'protocol': "HTTP", 'logline': logline}
    
# ThreatEnricher

class ThreatEnricher:
    def __init__(self, high_risk_usernames: list, high_risk_countries: list) -> None:
        self.high_risk_usernames = high_risk_usernames
        self.high_risk_countries = high_risk_countries

    def enrich(self, event: dict) -> dict:
        score = 0
        if event.get('username') in self.high_risk_usernames:
            score += 40
        if event.get('country') in self.high_risk_countries:
            score += 30
        if event.get('protocol') == "SSH":
            score += 20

        return {**event, 'threat_score': score}
    
    @staticmethod
    def is_valid_event(event: dict) -> bool:
        if event.get('src_ip') and event.get('protocol'):
            return True
        return False
    

# EventPipeline class

class EventPipeline:
    def __init__(self, enricher: ThreatEnricher) -> None:
        self._enricher = enricher
        self._processed: list = []


    def process(self, logline: str, metadata: dict, protocol: str) -> None:
        try:
            if(protocol == "ssh"):
                parsed = parse_ssh(logline, metadata)
            elif(protocol == "ftp"):
                parsed = parse_ftp(logline, metadata)
            elif(protocol == "http"):
                parsed = parse_http(logline, metadata)
            else:
                return None
            
            if parsed is None:
                return 

            if not ThreatEnricher.is_valid_event(parsed):
                return False

            self._processed.append(self._enricher.enrich(parsed)) 

        except:
            print("failed to process event")


    def get_high_risk(self, min_score: int) -> list:
        filtered = []
        for event in self._processed:
            if event.get('threat_score') >= min_score:
                filtered.append(event)
        return filtered
            

    def summary(self):
        return {'total': len(self._processed), 'high_risk': len(self.get_high_risk(60))}

            
enricher = ThreatEnricher(
    high_risk_usernames=["root", "admin"],
  high_risk_countries=["Russia", "China"]
)

pipeline = EventPipeline(enricher=enricher)

pipeline.process("ssh login", {"src_ip": "91.108.56.142", "username": "root", "country": "Russia"}, "ssh")
pipeline.process("ftp login", {"src_ip": "185.220.101.5", "username": "guest", "country": "Germany"}, "ftp")
pipeline.process("http request", {"src_ip": "1.2.3.4", "status_code": 200, "country": "China"}, "http")
pipeline.process("ssh login", {"username": "admin", "country": "Russia"}, "ssh")
pipeline.process("ftp login", {"src_ip": "2.2.2.2"}, "ftp")

print(pipeline.get_high_risk(min_score=60))
print(pipeline.summary())