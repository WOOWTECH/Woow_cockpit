"""Inspect bounded private errors, exporting only fixed diagnostic predicates."""
import sys,json,re
from pathlib import Path
root=Path(sys.argv[1]); fixture=json.loads((root/'probe-result.json').read_text())['fixture']; s=Path(fixture)/'client-state'
data=(s/'daemon.log').read_bytes()[:1024*1024].decode(errors='replace')
patterns=['connection reset by peer','EOF','network is unreachable','i/o timeout','no route to host','operation not permitted','proxyconnect','failed to fetch control key','failed to get control key','context canceled','register request','RegisterReq','register response','401 Unauthorized','400 Bad Request','tls:','x509:','health(warnable=login-state)','dial tcp','read tcp','http2','noise','key?v=','127.0.0.1:8080','arm54.invalid','login.tailscale.com','certificate','unexpected EOF','http: server gave HTTP response to HTTPS client','net/http: TLS handshake timeout']
result={'predicates':{p:p.lower() in data.lower() for p in patterns}}
# Export an ordered vocabulary of public error terms, never arbitrary log strings.
vocab=set('failed fetch control key Get dial tcp read write connect connection reset peer EOF network unreachable timeout TLS handshake x509 certificate unknown authority refused context deadline exceeded canceled proxy response status unauthorized login register noise protocol version unsupported localhost 127.0.0.1 8080 key v'.lower().split())
result['error_vocabulary']=[ [w for w in re.findall(r'[a-zA-Z]+',line.lower()) if w in vocab] for line in data.splitlines() if any(x in line.lower() for x in ('error','failed','timeout','fetch','login:','control:'))][-20:]
result['up_stderr_predicates']={p:p in (s/'up.stderr').read_text() for p in ['context deadline exceeded','timeout','To authenticate','Logged out','failed','no such file']}
import urllib.parse,ipaddress
result['url_targets']=sorted(set((urllib.parse.urlsplit(u).hostname,urllib.parse.urlsplit(u).port,('root' if not urllib.parse.urlsplit(u).path else 'other')) for u in re.findall(r'https?://[^"\s]+',data) if urllib.parse.urlsplit(u).hostname))
result['dial_targets']=[{'loopback':ipaddress.ip_address(ip).is_loopback,'unspecified':ipaddress.ip_address(ip).is_unspecified,'port':int(port)} for ip,port in re.findall(r'dial tcp (\d+\.\d+\.\d+\.\d+):(\d+)',data)]
result['key_endpoint_literal']=bool(re.search(r'https://127\.0\.0\.1:8080/key',data))
result['connect_ipv6_loopback']=('[::1]:8080' in data)
result['log_template_words']=sorted(set(re.findall(r'[a-zA-Z_]{3,30}',data.lower())) & set('login ts2021 bootstrap dns fallback resolve controlplane microsoft captive connectivity check http key sock proxy environment malformed failed permission denied operation permitted'.split()))
print(json.dumps(result,sort_keys=True))
