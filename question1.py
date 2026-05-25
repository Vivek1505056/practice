event = {
    'protocol' : "FTP",
    'src_ip' : "185.220.101.5",
    'username' : "root",
    'threat_score' : 78
}

print(event.get('src_ip'))

geo_data = {
    'country' : "Russia",
    'lat' : 55.75
}

enriched = {**event, **geo_data}

print(enriched.get('country'))

def parse_ftp_log(logline: str, metadata: dict) -> dict | None:
    if metadata.get('src_ip') == None:
        return None
    else:
        return {**metadata, "protocol" : "FTP", 'logline' : logline}
    
print(parse_ftp_log("ftp login attempt",{"src_ip": "185.220.101.5", "username":"root"}))

print(parse_ftp_log("ftp login attempt",{}))

def get_threat_level(score: int) -> str:
    if score >= 75:
        return "high"
    else:
        return "low"
    
print(get_threat_level(95))
print(get_threat_level(40))


def describe_event(event: dict) -> str:
    if not event.get('src_ip'):
        return "event has no source IP"
    elif event.get('threat_score') >= 75 and (event.get('country') == 'china' or event.get('country') == 'Russia'):
        return "high risk event"
    else:
        return "standard event"
    
print(describe_event({"src_ip": "185.220.101.5", "threat_score": 90, "country": "Russia"}))
print(describe_event({"src_ip": "1.2.3.4", "threat_score": 30, "country": "Germany"}))
print(describe_event({"threat_score": 90, "country":"Russia"}))
