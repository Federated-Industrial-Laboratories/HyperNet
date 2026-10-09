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
Explicit null is accepted only for optional ID, colour, border and motion fields.

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
| Panel | label | id, colour, border, motion, padding=1 (0-4) | One or more |
| ScrollBox | id, label, rows (2-40) | colour, border | One or more |
| Text | value (nonempty, at most 1024 bytes) | id, colour, motion, bold=false | None |
| Separator | None | colour | None |
| Spacer | rows (1-8) | None | None |
| Progress | label, value, maximum | id, colour, motion | None |
| Button | label, action | id, colour | None |
| Form | id, label, profile, recipient, owner | None | Direct Field and Submit children |
| Field | id, label, kind and its limits | required=false | None |
| Submit | label | None | None |
| Asset | id, profile, width, height, bytes, digest, hosts, copies | None | Declaration outside containers |
| Image | id, asset, alt, rows (1-40) | fit=Contain, motion | None |

Progress numbers are integers: maximum is 1 through 1000000 and value is zero
through maximum. A progress component displays supplied information; it neither
polls a service nor starts a task. Weight affects a direct Column child of a Row.
Other row children have weight one. Padding and gap use terminal cells.

The palette is Default, Black, Red, Green, Yellow, Blue, Magenta, Cyan, White,
BrightBlack, BrightRed, BrightGreen, BrightYellow, BrightBlue, BrightMagenta,
BrightCyan and BrightWhite. Names select logical terminal colours. They cannot
modify the terminal palette or supply escape sequences. Themes determine actual
colour values. Readers may disable colour or override presentation.

### Border styles

Panel and ScrollBox accept an optional `border`: Light, Heavy, Double, Rounded
or Ascii. An omitted or null border inherits the enclosing border style through
intervening containers. The top-level default is Light. A nested explicit style
applies within that container without changing siblings. Separator uses its
enclosing style and has no border attribute.

| Style | Horizontal / vertical | Corners, clockwise from top left | Left / right / top / bottom / crossing junctions |
| --- | --- | --- | --- |
| Light | `─` / `│` | `┌ ┐ ┘ └` | `├ ┤ ┬ ┴ ┼` |
| Heavy | `━` / `┃` | `┏ ┓ ┛ ┗` | `┣ ┫ ┳ ┻ ╋` |
| Double | `═` / `║` | `╔ ╗ ╝ ╚` | `╠ ╣ ╦ ╩ ╬` |
| Rounded | `─` / `│` | `╭ ╮ ╯ ╰` | `├ ┤ ┬ ┴ ┼` |
| Ascii | `-` / `\|` | `+ + + +` | `+ + + + +` |

These finite styles select terminal box-drawing characters. Authors cannot supply
arbitrary glyph maps, terminal commands or executable style expressions. Separators
that span a Panel or ScrollBox's content width extend through that container's
own padding and join its sides. Separators in narrower or padded child containers
remain inset and clipped. Current horizontal separators use left/right junctions;
the glyph families do not introduce a grid layout. A reader may force ASCII
presentation for every style. Border choice does not change layout bounds or
motion permissions. Rendering preserves the exact signed source bytes.

```text
@Panel {"label":"Opening hours","border":"Rounded"}
: Monday through Friday
@Separator {}
: 09:00 to 17:00
@End
```

## Actions and references

Buttons accept exactly one of these objects:

```json
{"kind":"Navigate","target":"https://example.com/"}
{"kind":"Focus","target":"Guide"}
{"kind":"Scroll","target":"Guide","direction":"End"}
{"kind":"Reveal","target":"Picture"}
{"kind":"Motion","target":"Banner","running":false}
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

Reveal targets an Image ID; Motion targets a component with a declared effect.
Unknown syntax and executable handlers are rejected during submission and proof
verification. Neither action provides a URL or arbitrary command.

## Static media and local motion

An Asset declaration binds one exact static object. IDs follow the component ID
syntax and are unique within the asset list. Every declared asset must appear in
an Image; every Image must resolve its asset. Asset and component IDs have separate
namespaces. At most eight assets and 4 MiB of canonical bytes are allowed per page.
Each dimension is 1 through 1024, with at most 262144 pixels. `digest` is the exact
bytes' SHA-256, encoded as 64 lowercase hexadecimal characters. `hosts` contains
one through three distinct 64-character host keys, never addresses or URLs.
`copies` is 1 through the host count; administrator policy can require more.

`HyperNetRaster/1` contains exactly width * height * 3 bytes of row-major RGB8,
left-to-right and top-to-bottom, without metadata, headers, padding or animation.
`HyperNetVector/1` contains canonical geometry as specified below, at most 256 KiB.
The same size, manifest, digest and geometry checks apply to imports, sealed
storage, moderation and independent client reads.

Image `alt` is required, nonempty visible text of at most 128 bytes. `rows` reserves
a bounded viewport within normal page flow. `fit` is Contain or Cover. Images do
not replace semantic text, controls, responsive layout or browser chrome. Clients
start with alt text and fetch only after explicit reveal. Missing support, revoked
access, unknown geometry or exhausted display budgets retain the labelled fallback.
The publication binds all alt text, manifests, placement policy and effect settings.

A `motion` object contains exactly `preset` and integer `durationMs` (1000-10000).
Text permits ColourPulse, TextFade or TextScroll; Panel permits BorderEmphasis;
Progress permits ProgressSweep; Image permits ImagePan or ImageFade. Defaults are
static. An explicit local activation lasts at most ten seconds. Clients provide
pause/reduced-motion controls, stop hidden effects, and limit active visible effects
to eight. They paint at most ten text frames and two bitmap frames per second.
ProgressSweep is decorative and does not change the reported numeric progress.

The protocol sends static source, static assets and preset parameters. Viewers
generate every effect frame locally. Effects cannot request frames, poll a service,
fetch another asset, introduce scripts or supply an author-defined frame sequence.
A graphical client may implement the same bounded presets in its own renderer.

## Retained vector geometry

`HyperNetVector/1` is strict canonical UTF-8 JSON. The top-level fields, in order,
are `profile`, `width`, `height`, `background` and `paths`. Background is three
RGB8 integers. Paths are in painting order, at most 512. Each path has `commands`,
`fill`, `stroke` and `fillRule`, in that order. Fill is null or four RGBA8 integers.
Stroke is null or `{ "colour": [R,G,B,A], "width": INTEGER }`. At least one paint
must exist. FillRule is NonZero or EvenOdd. Stroke uses butt caps, miter joins and
miter limit four. Later paths composite over earlier paths and the opaque background.

Coordinates and stroke widths use 1024 integer units per pixel. Coordinate absolute
values are at most 16777216; stroke width is 1 through 65536. The viewport clips all
geometry. Width/height must match the asset manifest. These commands use a `kind`
tag first, followed by the listed fields in order:

| kind | Fields |
| --- | --- |
| Move | x, y |
| Line | x, y |
| Quad | x1, y1, x, y |
| Cubic | x1, y1, x2, y2, x, y |
| Close | None |

A path begins with Move. Close ends the current contour; another command then
requires Move. Each path has 1-2048 commands, and the object has at most 8192 total.
Unknown/duplicate fields, fractions, resource references, expressions and strings
in coordinates fail. Canonical encoding has no whitespace, omitted optional fields,
trailing newline or alternative field order; null paint fields are explicit.

SVG import converts the documented static subset into this representation inside
a confined worker. Original XML, active content, resource references and animation
are not published. The import report identifies removed content; unsupported visual
features fail. Developers can render the typed geometry directly or export it as a
minimal static SVG containing numeric paths and literal paints. No SVG engine or
XML parser is required in HyperNet infrastructure. Logical page reflow, labels,
focus and permissions remain HyperPage responsibilities in every viewer.

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
Media includes every manifest, host/copy policy, alt label, fit and effect preset.
Plain output emits no pixels, animation or network request.
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
