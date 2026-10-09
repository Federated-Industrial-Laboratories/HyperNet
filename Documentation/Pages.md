# Pages

HyperNetPage/1 is an inert text format. The source bytes are immutable within a
submission. Approval binds the exact bytes, author, network, namespace, audience
and parser profile. Any source change requires another submission and review.

## Text profile

The first two lines are the exact profile header and a nonempty title:

```text
HyperNetPage/1
# Welcome
: A paragraph of information.
## Notices
- A list item
> A quotation
| A literal example, never a command to execute
=> https://example.com/ External reference
```

After the title, blank lines and these prefixes are recognised: `## ` and `### `
for headings, `: ` for paragraphs, `- ` for list items, `> ` for quotes, `| ` for
literal text, and `=> ` for explicit links. Other prefixes are rejected. Each
nonempty block contains non-whitespace text. There is no nesting, inline
expression, executable macro, import, script, HTML interpretation or automatic
action. HTML-like characters inside a text block remain literal text. Images
and terminal graphics are not part of this profile.

A source is strict UTF-8, at most 16 KiB, with LF line endings and a final LF.
There are at most 512 lines, each at most 1024 UTF-8 bytes and 512 extended
grapheme clusters. Each cluster has at most 16 Unicode scalar values. Titles
and link labels are at most 128 bytes. Source is neither normalised nor
reformatted before hashing or signing. Grapheme segmentation is pinned to
unicode-segmentation 1.13.3; a change to parsing semantics requires a new profile.

C0/C1 controls, DEL, carriage returns, tabs, directional formatting controls,
Unicode line/paragraph separators, BOM, soft hyphen, zero-width space, tag
characters and Unicode noncharacters are rejected. ZWJ/ZWNJ remain available
within the cluster limits. Plain output has an ASCII escape option for terminals
whose Unicode rendering is unsuitable. An approval is not a guarantee that
the content is harmless or truthful.

Links have the form `=> TARGET LABEL`. Targets are ASCII, at most 512 bytes.
An internal target is:

```text
hypernet://NETWORK_HEX/AUTHOR_HEX/Namespace/PAGE_ID_HEX
```

Network and author values are 32-byte lowercase hexadecimal identities; the
page ID is 16 bytes. A namespace matches `[A-Za-z][A-Za-z0-9]{0,31}`. Clients
check the returned author and namespace against an internal link. A link to
another network requires separately configured trust; it does not create trust.
External targets are canonical HTTPS URLs without user information. They are
displayed as references and are never fetched or opened automatically.

The authority and independent Suite keep the same conformance vectors in
`Tests/MarkupVectors.json`. Only application-generated controls may reach a
terminal. Page text cannot set a title, write a clipboard or generate terminal
graphics. Trusted approval information is displayed separately from content.

## Scoped applications

A member can delegate selected native Page operations to a distinct application
identity. Permissions intersect explicit namespaces and optional page IDs.
Review delegation additionally requires an administrator owner and a bound policy
and mode; ordinary manual review remains the default. Application signatures keep
their actual author or reviewer key. Fresh publication checks require that grant
and its owner to retain the required rights. See [Applications](Applications.md)
and the independent [application API](ApplicationProtocol.md).
