from . import server

Connection = server.ProxyURI.compile_relay
DIRECT = server.ProxyURI.DIRECT
Server = server.ProxyURI.compile
Rule = server.ProxyURI.compile_rule
