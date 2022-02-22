# TM28

## About

[**TM28**](https://bulbapedia.bulbagarden.net/wiki/TM28) is a command-line DNS client built as learning exercise to better understand how DNS works.

## Run

Currently TM28 is **very** limited and only allows querying for A, CNAME, NS, MX Records

```
cargo run {domain}
```

## Acknowledgments

Canonical source for all information is [RFC 1035: DOMAIN NAMES - IMPLEMENTATION AND SPECIFICATION](https://www.ietf.org/rfc/rfc1035.txt)

This project also draws heavy inspiration from Emil Hernvall's [DNS Guide](https://github.com/EmilHernvall/dnsguide), Paul Carleton's [Dumb Dig Clone](https://pcarleton.com/2018/02/19/drt-dns-dig/), and Duke University's [DNS Primer](https://courses.cs.duke.edu//fall16/compsci356/DNS/DNS-primer.pdf)
