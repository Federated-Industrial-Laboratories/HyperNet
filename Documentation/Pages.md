# Pages

HyperNetPage/2 is an inert text format. The source bytes are immutable within a
submission. Approval binds the exact bytes, author, network, namespace, audience
and parser profile. Any source change requires another submission and review.

## Current document contract

The [HyperPage specification](HyperPage.md) defines the complete current grammar,
component attributes, layout bounds, actions and conformance vectors. Containers,
scrollboxes, progress values and buttons remain declarative. No script, import,
HTML interpretation, arbitrary API command or automatic action is permitted.

The source is at most 16 KiB. It is not normalised or reformatted before hashing.
Approval binds the exact source and parser profile. Only HyperNetPage/2 is accepted;
retired profiles cannot acquire new semantics through an executable update.
Grapheme segmentation is pinned to unicode-segmentation 1.13.3. Changes to accepted
semantics require an explicit contract and signature-domain assessment.

Forms, media and animation attributes remain rejected until their complete
permission and presentation contracts are implemented. Plain moderation output
includes all container contents and action destinations, including text outside
the initial scrollbox viewport. Approval does not guarantee harmless or truthful
content. Reader colour and layout preferences cannot change the approved bytes.

## Scoped applications

A member can delegate selected native Page operations to a distinct application
identity. Permissions intersect explicit namespaces and optional page IDs.
Review delegation additionally requires an administrator owner and a bound policy
and mode; ordinary manual review remains the default. Application signatures keep
their actual author or reviewer key. Fresh publication checks require that grant
and its owner to retain the required rights. See [Applications](Applications.md)
and the independent [application API](ApplicationProtocol.md).
