# M77 Research Notes

Accessed 2026-08-15. These notes preserve the authoritative sources used for M77 design.

## W3C PROV-DM

Source: [W3C PROV-DM](https://www.w3.org/TR/prov-dm/), W3C Recommendation, 30 April 2013.

The specification defines provenance as information about entities, activities, and agents involved in producing or influencing a data item. Its core model distinguishes entities, activities, agents, generation, usage, communication, derivation, attribution, association, and delegation. M77 maps a fetched source representation to an entity, retrieval/cross-check operations to activities, and the research service/browser session to agents. This supports retaining provenance links without treating provenance metadata as proof of semantic truth.

## IETF HTTP Semantics

Source: [RFC 9110 — HTTP Semantics](https://httpwg.org/specs/rfc9110.html), Internet Standards Track, June 2022.

RFC 9110 defines HTTP as a stateless application-level request/response protocol and distinguishes resource representations, response metadata, status codes, and validator fields. It specifies date/time field syntax and fields such as `Date`, `Last-Modified`, and `ETag`; M77 records these as source-reported metadata and separately records local retrieval time. HTTP response success does not establish that content is true, current, or authoritative. M77 therefore treats HTTP status and metadata as evidence attributes, not verification decisions.

## NIST integrity verification

Source: [NIST CSRC Glossary — Integrity verification](https://csrc.nist.gov/glossary/term/integrity_verification), citing NIST SP 800-152.

NIST defines integrity verification as obtaining assurance that information has not been altered without authorization since creation, transmission, or storage. M77 applies a SHA-256 content digest to retained source content and records it in the provenance record. Digest equality establishes content identity for the retained bytes; it does not establish authorship, accuracy, freshness, or semantic truth.

## Implementation consequences

| Source conclusion | M77 consequence |
|---|---|
| Provenance links entities, activities, and agents | Source records retain URL, content digest, retrieval activity, browser/session evidence, and verification activity identifiers |
| HTTP metadata describes representations and response context | Record local retrieval time separately from source-reported publication/modified time and preserve missing metadata as unknown |
| Integrity verification concerns unauthorized alteration | Digest content at ingestion and cross-check; never convert digest equality into semantic truth |
| Protocol success is not knowledge truth | Require explicit verification state before promoting any source claim into M73 world state |
| Provenance helps assessments but does not itself rank truth | Use bounded primary-source preference and cross-check policy; retain conflicts instead of choosing a silent winner |

## Limitations

These sources do not define an AGI truth oracle, source-ranking policy for every domain, or prompt-injection defense. M77 must remain a bounded userspace service. Browser/page/model text is data and cannot grant kernel authority or verification status.

## References

[1]: https://www.w3.org/TR/prov-dm/ "W3C PROV-DM: The PROV Data Model"
[2]: https://httpwg.org/specs/rfc9110.html "RFC 9110: HTTP Semantics"
[3]: https://csrc.nist.gov/glossary/term/integrity_verification "NIST CSRC Glossary: Integrity verification"
