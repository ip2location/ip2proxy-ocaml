(lang dune 3.4)

(name ip2proxy)

(version 3.2.0)

(generate_opam_files true)

(source
 (github ip2location/ip2proxy-ocaml))

(authors "IP2Location.com")

(maintainers "IP2Location.com")

(license MIT)

(documentation https://github.com/ip2location/ip2proxy-ocaml)

(package
 (name ip2proxy)
 (synopsis "IP2Proxy OCaml module to get proxy data")
 (description "IP2Proxy OCaml module enables user to query an IP address if it was being used as VPN anonymizer, open proxies, web proxies, Tor exits, data center, web hosting (DCH) range, search engine robots (SES), AI crawlers (AIC), residential proxies (RES), consumer privacy networks (CPN), and enterprise private networks (EPN).")
 (depends (ocaml (>= "4.08")) dune stdint (ipaddr (>= "4.0.0")))
 (tags (ip2proxy proxy)))

; See the complete stanza docs at https://dune.readthedocs.io/en/stable/dune-files.html#dune-project
