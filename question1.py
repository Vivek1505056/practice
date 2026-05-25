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

