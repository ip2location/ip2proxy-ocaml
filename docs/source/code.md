# IP2Proxy OCaml API

## Database Class

```{py:function} open_db(bin_path)
Load the IP2Proxy BIN database for lookup.

:param str bin_path: (Required) The file path links to IP2Proxy BIN databases.
```

```{py:function} close_db()
Closes the BIN file.
```

```{py:function} query(ip)
Retrieve geolocation information for an IP address.

:param string ip: (Required) The IP address (IPv4 or IPv6).
:return: Returns the geolocation information in array. Refer below table for the fields avaliable in the array
:rtype: array

**RETURN FIELDS**

| Field Name       | Description                                                  |
| ---------------- | ------------------------------------------------------------ |
| is_proxy         |     Determine whether if an IP address was a proxy or not. Returns 0 if not proxy, 1 if proxy, and 2 if it's data center IP |
| country_short    |     Two-character country code based on ISO 3166. |
| country_long     |     Country name based on ISO 3166. |
| region           |     Region or state name. |
| city             |     City name. |
| isp              |     Internet Service Provider or company\'s name. |
| domain           |     Internet domain name associated with IP address range. |
| usage_type       |     Usage type classification of ISP or company. |
| asn              |     Autonomous system number (ASN). |
| as               |     Autonomous system (AS) name. |
| last_seen        |     Proxy last seen in days. |
| threat           |     Security threat reported. |
| proxy_type       |     Type of proxy. |
| provider         |     Name of VPN provider if available. |
| fraud_score      |     Potential risk score (0 - 99) associated with IP address. |
```