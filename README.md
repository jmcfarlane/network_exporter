# network_exporter

An experiment on solving the following:

1. Not wanting to use `CAP_NET_RAW` with containers
   - Which [cannot](https://github.com/digineo/go-ping/issues/12) currently
     work as [documented](https://github.com/czerwonk/ping_exporter/pull/51)
     anyway :/
1. Refusal to run as root (see above)
1. Lack of metrics around DNS

## Credit

https://github.com/prometheus-community/pro-bing

## Inspired by

- https://github.com/czerwonk/ping_exporter
- https://github.com/digineo/go-ping
