# HyperPage format

`HyperNetPage/2` is the current inert document profile. Other profiles are rejected.
A signature binds the exact source bytes and profile. Parsing and rendering never
normalize or replace those bytes before hashing or review.

## Source and structure

Use UTF-8, LF line endings and a final LF. The first line is `HyperNetPage/2`.
The second is `# Title`, with a nonempty title of at most 128 bytes. The source
limit is 16 KiB and 512 lines. Each line has at most 1024 bytes, 512 grapheme
clusters and 16 Unicode scalars per cluster. Control characters, bidi formatting,
Unicode line separators, zero-width space, soft hyphen, tags, BOM and noncharacters
are rejected. The same restrictions apply after JSON string decoding.

Text lines use `## ` or `### ` for headings, `: ` for paragraphs, `- ` for items,
`> ` for quotations and `| ` for literal text. These prefixes require nonempty
text. A blank line adds a one-row spacer. Literal text has no executable meaning.

Components use `@Name {attributes}` on one line. Containers end with `@End` on
its own line. Leading indentation is rejected. Component names, attributes,
IDs and colour names are case-sensitive. Unknown fields, duplicate JSON keys at
any depth, fractional numbers, invalid bounds and unresolved references fail.
Explicit null is accepted only for optional ID and colour fields.

At most 256 nodes, eight tree levels and 64 controls are allowed. Text lines,
spacers and containers each count as one node; title and `@End` do not. Controls
are buttons, scrollboxes and form fields. Containers must have at least one child. IDs begin
with an ASCII letter, contain only ASCII letters/digits and have at most 32 bytes.
Component and form IDs are unique within the document. Field IDs are unique within their form. Labels have at most 128 bytes.

## Components

An optional `colour` uses the palette below. An omitted colour inherits its
container's colour. `Default` explicitly selects the terminal default. An
optional `id` follows the ID rule above.

| Name | Required attributes | Optional attributes and defaults | Children |
| --- | --- | --- | --- |
| Column | None | id, colour, weight=1 (1-8), padding=0 (0-4), gap=0 (0-4) | One or more |
| Row | None | id, colour, minChildColumns=24 (12-120), gap=1 (0-4) | One through eight |
| Panel | label | id, colour, padding=1 (0-4) | One or more |
| ScrollBox | id, label, rows (2-40) | colour | One or more |
| Text | value (nonempty, at most 1024 bytes) | colour, bold=false | None |
| Separator | None | colour | None |
| Spacer | rows (1-8) | None | None |
| Progress | label, value, maximum | colour | None |
| Button | label, action | id, colour | None |
| Form | id, label, profile, recipient, owner | None | Direct Field and Submit children |
| Field | id, label, kind and its limits | required=false | None |
| Submit | label | None | None |

Progress numbers are integers: maximum is 1 through 1000000 and value is zero
through maximum. A progress component displays supplied information; it neither
polls a service nor starts a task. Weight affects a direct Column child of a Row.
Other row children have weight one. Padding and gap use terminal cells.

The palette is Default, Black, Red, Green, Yellow, Blue, Magenta, Cyan, White,
BrightBlack, BrightRed, BrightGreen, BrightYellow, BrightBlue, BrightMagenta,
BrightCyan and BrightWhite. Names select logical terminal colours. They cannot
modify the terminal palette or supply escape sequences. Themes determine actual
colour values. Readers may disable colour or override presentation.

## Actions and references

Buttons accept exactly one of these objects:

```json
{"kind":"Navigate","target":"https://example.com/"}
{"kind":"Focus","target":"Guide"}
{"kind":"Scroll","target":"Guide","direction":"End"}
```

Focus and Scroll targets must identify a ScrollBox in the same document. Forward
references are allowed. Scroll direction is Up, Down, Start or End. An action
does nothing until the reader explicitly activates its control.

Navigate accepts canonical HTTPS references without user information or an exact
native URI: `hypernet://NETWORK/AUTHOR/Namespace/PAGE`. NETWORK and AUTHOR are
64 lowercase hexadecimal characters; PAGE is 32. Namespace follows the ID rule.
Targets are ASCII, have at most 512 bytes and contain no spaces or controls.
HTTPS references are displayed as external references; they are not fetched or
opened automatically. Native navigation requires the client's configured network
or an explicitly authorised federation agreement and fresh verified content.

The compact `=> TARGET LABEL` line creates a navigation button. Its label follows
the same bounds. A display label never substitutes for the actual destination.

Media, animation and executable handlers are not accepted by this profile's
current implementation. Unknown syntax is rejected during submission and proof
verification. It cannot be published as an inert placeholder for later actions.

## Declarative forms

A Form declares the `HyperNetFormMail/1` action profile. Its recipient is a
same-network mailbox address, and owner is that mailbox owner's fingerprint.
Both are exactly 64 lowercase hexadecimal characters. The page cannot supply a
URL, certificate, path, executable handler or automatic trust decision.

Each page has at most four forms. A form has one through 16 direct Field children
and exactly one direct Submit child. Other children and nested forms are rejected.
Fields cannot supply defaults, hidden values, passwords, autofill, file inputs,
regular expressions or local machine data. The source attributes are:

| kind | Required limits | Accepted value |
| --- | --- | --- |
| Text | maxBytes (1-2048) | UTF-8 string without controls |
| Multiline | maxBytes (1-2048) | UTF-8 string; LF is the only permitted control |
| Integer | minimum, maximum | Integer in the inclusive signed 64-bit range |
| Boolean | None | JSON true or false |
| Choice | options | One exact string from the list |

All fields require id and label. The optional required flag defaults to false.
Unknown or inapplicable attributes fail, including null required flags and limits.
Integer minimum must not exceed maximum. Choices contain one through 16 distinct,
nonempty strings, each at most 128 bytes. Text values reject the same Unicode
formatting controls as source text, with at most 16 scalars per grapheme cluster.
Multiline byte bounds include LF bytes. Required text cannot be empty or only
whitespace. Required Boolean false is a valid answer. Missing optional fields are
omitted; null and additional undeclared values are rejected.

The schema digest is SHA-256 over the exact source bytes from the opening @Form
line through its matching @End line, including the final LF. Destination, labels,
limits, choice order and submit label therefore affect that digest. Surrounding
page text does not. The complete signed page bundle still binds every source byte.

A form-bearing publication has a maximum 20 KiB serialized signed bundle. The
infrastructure checks the actual complete bundle before publication and on proof
verification. The author client reserves the maximum permitted 4 KiB approval
before uploading a form draft. Local preview uses maximum submission metadata as
well, so its bound is conservative. Ordinary pages retain their existing limits.
Serialized typed values have an 8 KiB limit, including JSON escaping and keys.
The submission client separately checks the complete 32 KiB encrypted-mail body.

Submit opens a trusted review; it cannot send by itself. The client requires an
explicit sending mailbox, an already verified recipient contact, a fresh approved
page and fresh destination metadata. A separate confirmation queues one immutable
encrypted message. Local preview and moderation cannot submit. Foreign federation
pages do not gain cross-network mail actions from this profile.

Receivers independently accept an exact approved page version and form schema
before recognizing typed form messages. A valid signature alone does not establish
publication authority or acceptance. Receiving data never executes an action.

```text
@Form {"id":"Feedback","label":"Feedback","profile":"HyperNetFormMail/1","recipient":"0101010101010101010101010101010101010101010101010101010101010101","owner":"0202020202020202020202020202020202020202020202020202020202020202"}
@Field {"id":"Message","label":"Message","kind":"Multiline","maxBytes":1024,"required":true}
@Field {"id":"Priority","label":"Priority","kind":"Choice","options":["Normal","Urgent"]}
@Submit {"label":"Review feedback"}
@End
```

## Layout and plain output

Rows divide available columns using their direct children's weights. They stack
in document order when minimum widths cannot fit. Text wraps by grapheme cell
width. Panels and scrollboxes clip all descendants to their rectangles. There is
no absolute positioning, overlay, raw terminal protocol or page-controlled browser
chrome. Reader layout work and terminal dimensions are bounded independently of
source bounds.

Plain output includes all text, scrollbox contents, progress values, button labels
and destinations in document order. Forms include their profile, recipient, owner,
schema digest, every field type, limit, choice, required flag and submit label.
Output does not depend on which content initially
fits the screen. Moderation must expose all of these values. A renderer may not
discard unknown critical semantics and continue displaying an approved page.

## Example

```text
HyperNetPage/2
# Workshop
@Panel {"label":"Welcome","colour":"Cyan"}
@Row {"minChildColumns":24,"gap":2}
@Column {"weight":1}
## Noticeboard
: This text wraps when the terminal becomes narrow.
@Progress {"label":"Checklist","value":2,"maximum":3}
@End
@ScrollBox {"id":"Guide","label":"Guide","rows":4}
: Every line remains available through scrolling or plain output.
=> https://example.com/ External reference
@End
@End
@Button {"label":"Read guide","action":{"kind":"Focus","target":"Guide"}}
@End
```

`Tests/MarkupVectors.json` contains accepted and rejected conformance cases.
The infrastructure and independent Suite validate the same contract and retain
their own parser and tests. The Suite is not a daemon dependency.
