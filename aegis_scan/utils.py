import re
from typing import List


def parse_ports(ports_str: str) -> List[int]:
    ports = set()
    parts = re.split(r"\s*,\s*", ports_str.strip())
    for p in parts:
        if not p:
            continue
        if "-" in p:
            a, b = p.split("-", 1)
            a_i = int(a)
            b_i = int(b)
            for v in range(a_i, b_i + 1):
                if 1 <= v <= 65535:
                    ports.add(v)
        else:
            v = int(p)
            if 1 <= v <= 65535:
                ports.add(v)
    return sorted(ports)
