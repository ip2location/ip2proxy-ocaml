# IP2Proxy OCaml Module
[![Static Badge](https://img.shields.io/badge/OPAM-ip2proxy-blue)](https://opam.ocaml.org/packages/ip2proxy/)

This OCaml module allows user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES), residential proxies (RES), consumer privacy networks (CPN), and enterprise private networks (EPN). It supports both IP address in IPv4 and IPv6.

## Developer Documentation
To learn more about installation, usage, and code examples, please visit the developer documentation at [https://ip2proxy-ocaml.readthedocs.io/en/latest/](https://ip2proxy-ocaml.readthedocs.io/en/latest/).



### Proxy Type

|Proxy Type|Description|
|---|---|
|VPN|Anonymizing VPN services|
|TOR|Tor Exit Nodes|
|PUB|Public Proxies|
|WEB|Web Proxies|
|DCH|Hosting Providers/Data Center|
|SES|Search Engine Robots|
|RES|Residential Proxies [PX10+]|
|CPN|Consumer Privacy Networks. [PX11+]|
|EPN|Enterprise Private Networks. [PX11+]|

### Usage Type

|Usage Type|Description|
|---|---|
|COM|Commercial|
|ORG|Organization|
|GOV|Government|
|MIL|Military|
|EDU|University/College/School|
|LIB|Library|
|CDN|Content Delivery Network|
|ISP|Fixed Line ISP|
|MOB|Mobile ISP|
|DCH|Data Center/Web Hosting/Transit|
|SES|Search Engine Spider|
|RSV|Reserved|

### Threat Type

|Threat Type|Description|
|---|---|
|SPAM|Email and forum spammers|
|SCANNER|Security Scanner or Attack|
|BOTNET|Spyware or Malware|
|BOGON|Unassigned or illegitimate IP addresses announced via BGP|