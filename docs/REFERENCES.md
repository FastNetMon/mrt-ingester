# MRT-RS References and Attribution

## RFC Documents

This library implements the MRT (Multi-threaded Routing Toolkit) format as specified in the following IETF RFCs:

### RFC 6396 - Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format

- **URL**: https://datatracker.ietf.org/doc/html/rfc6396
- **Authors**: L. Blunk, M. Karir, C. Labovitz
- **Date**: October 2011
- **Status**: Standards Track

This is the primary specification for the MRT format, defining:
- MRT common header format
- BGP4MP message types
- TABLE_DUMP and TABLE_DUMP_V2 formats
- IS-IS, OSPF, and RIP record types

### RFC 8050 - Multi-Threaded Routing Toolkit (MRT) Routing Information Export Format with BGP Additional Path Extensions

- **URL**: https://datatracker.ietf.org/doc/html/rfc8050
- **Authors**: C. Petrie, T. King
- **Date**: May 2017
- **Status**: Standards Track

This RFC extends RFC 6396 with support for BGP Add-Path (RFC 7911), adding:
- RIB_IPV4_UNICAST_ADDPATH
- RIB_IPV4_MULTICAST_ADDPATH
- RIB_IPV6_UNICAST_ADDPATH
- RIB_IPV6_MULTICAST_ADDPATH
- RIB_GENERIC_ADDPATH

### RFC 6397 - Multi-Threaded Routing Toolkit (MRT) Border Gateway Protocol (BGP) Routing Information Export Format with Geo-Location Extensions (Optional)

- **URL**: https://datatracker.ietf.org/doc/html/rfc6397
- **Authors**: T. Manderson
- **Date**: October 2011
- **Status**: Standards Track

Optional extension for geo-location information in MRT records.

## IETF Trust License Notice

The RFC documents referenced above are published by the Internet Engineering Task Force (IETF) and are subject to the IETF Trust's Legal Provisions (BCP 78).

Per the IETF Trust's terms:
- Redistribution of unmodified RFC documents is permitted
- Code components within RFCs are available under the Simplified BSD License
- See https://trustee.ietf.org/documents/trust-legal-provisions/ for full terms

## Data Sources for Testing

### RouteViews Project
- **URL**: http://www.routeviews.org/
- **Archive**: http://archive.routeviews.org/
- Provides historical and real-time BGP routing data in MRT format

### RIPE RIS (Routing Information Service)
- **URL**: https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris
- **Raw Data**: https://www.ripe.net/analyse/internet-measurements/routing-information-service-ris/ris-raw-data
- European source for MRT-formatted BGP data

### Isolario Project
- **URL**: https://www.isolario.it/
- Italian BGP data collection project

## Related Standards

### BGP Protocol
- **RFC 4271**: A Border Gateway Protocol 4 (BGP-4)
- **RFC 4760**: Multiprotocol Extensions for BGP-4
- **RFC 6793**: BGP Support for Four-Octet Autonomous System (AS) Number Space
- **RFC 7911**: Advertisement of Multiple Paths in BGP (Add-Path)

### Address Families
- **RFC 4760**: Defines AFI (Address Family Identifier) values
  - AFI 1 = IPv4
  - AFI 2 = IPv6

## Acknowledgments

This library is designed to be API-compatible with the original `mrt-rs` crate structure while providing an implementation under a more permissive license (MIT OR Apache-2.0).
