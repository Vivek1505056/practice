import asyncio
from contextlib import asynccontextmanager

async def lookup_threat_score(ip: str) -> int:
    await asyncio.sleep(0.1)
    
    if ip[0:3] == "91.":
        return 90
    else:
        return 20
    
async def enrich_event(event: dict) -> dict:
    score = await lookup_threat_score(event.get('src_ip'))

    return {**event, 'threat_score': score}


async def enrich_all(events: list) -> list:
    dolist =[]
    for event in events:
        dolist.append(asyncio.create_task(enrich_event(event)))

    mylist = []

    for event in dolist:
        mylist.append(await event)

    return mylist

@asynccontextmanager
async def managed_enricher(src_ip: str):
    print(f"starting enrichment for {src_ip}")
    yield {"src_ip": src_ip, "status": "active"}
    print(f"finished enrichment for {src_ip}" )


class  EventEnricher:
    def __init__(self, prefix: str) -> None:
        self._prefix = prefix
        self._log: list = []


    async def process(self, event: dict) -> dict:
        await asyncio.sleep(0.05)
        self._log.append({**event, "processed_by": self._prefix})

        return {**event, "processed_by": self._prefix}
    
    def get_log(self) -> list:
        return self._log


async def main():
    event1 = {'src_ip': '91.108.56.142'}
    event2 = {'src_ip': '1.2.3.4'}

    events = [
      {"src_ip": "91.108.56.142"},
      {"src_ip": "1.2.3.4"},
      {"src_ip": "91.220.101.5"},
    ]
        
    results = await enrich_all(events)
    print(results)

    print(await enrich_event(event1))
    print(await enrich_event(event2))

    async with managed_enricher("91.108.56.142") as session:
        print(session)

    
    enricher = EventEnricher(prefix="geo-enricher")
    r1 = await enricher.process({"src_ip": "91.108.56.142"})
    r2 = await enricher.process({"src_ip": "1.2.3.4"})
    print(r1)
    print(r2)
    print(enricher.get_log())

    
asyncio.run(main())



