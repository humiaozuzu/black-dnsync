# Black DNSync

A cli tool for managing DNS records with conf file

## Supported DNS Service provider

- Aliyun Intl
- Dnspod
- Dnsimple

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
www A hk-ali01
```
A record config also support not only IP but also ssh hostname

## TODO

- Aliyun CN
- CloudXNS
