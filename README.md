# Black DNSync

A interactive cli tool for managing DNS records with conf file

## Supported DNS Service provider

- Aliyun DNS Intl
- DNSPod
- DNSimple

## How to use

```
# sync existing remote records to local
blackdnsync --export --domain domain --provider dnspod --app-id id --app-key key

# sync local config to remote
blackdnsync --sync -c path_to_config.conf [--quite] [--dry-run]
```

available providers are dnspod/aliyun/dnsimple

## Example conf

```
[General]
domain = cat.sb
default-ttl = 600
provider = aliyun
app-id = 1as0P9F4Ivk0uI8x
app-key = xssCB4e4BdCxsMcm33iRNyvqyCzy

[Records]
# mailgun
@ MX mxa.mailgun.org priority=10
@ MX mxb.mailgun.org priority=10
@ TXT "v=spf1 include:mailgun.ors ~all"

@ A 1.1.1.1
www A hk-ali01 line=ct ttl=120
```
A record value support not only IP but also ssh hostname

### Line support

- DNSpod: ct/cu/cm/edu/oversea
- Aliyun DNS Intl: ct/cu/cm/edu/oversea
- DNSimple: no


## TODO

- Aliyun CN
- CloudXNS
