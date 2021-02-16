from . import server

Connection = server.proxies_by_uri
Server = server.proxy_by_uri
Rule = server.compile_rule
DIRECT = server.DIRECT
