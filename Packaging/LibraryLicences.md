# System library notices

The local OCI packager copies the shared libraries required by the supplied
executables. `Documentation/SystemLibraries.tsv` identifies each copied file,
its SHA-256 digest and the installed binary and source package versions.
`Documentation/SystemLibraryNotices.txt` contains the owning packages' copyright
notices and the relevant complete GNU licence texts. The GCC package notice
includes the GCC Runtime Library Exception.

The package tool currently reads Debian-format package ownership records. Its
library dependencies are copied dynamically; the build does not embed a private
static copy of the C library. Keep replacement shared libraries compatible with
the declared ABI when rebuilding the image with a modified library. The image
construction instructions and unstripped source build are available in this
repository. No prohibition on reverse engineering library modifications is added.

A local candidate image is not a distribution release. Before distributing it,
provide corresponding source for the exact library source packages and versions
listed in the inventory, using a method permitted by their licences. On a matching
Debian or Ubuntu system with source repositories enabled, `apt-get source
SourcePackage=SourceVersion` obtains the source package and distribution patches.
Retain that exact source alongside a distributed binary when selecting source
accompaniment; an upstream version alone omits distribution changes. The local
packager records these requirements but does not fetch or publish source packages.

Rust dependency notices are supplied separately in `ThirdPartyNotices.txt`.
Preserve those notices, this system-library inventory and the HyperNet MIT licence
when preparing a distribution package. Consult the included licence texts for
the applicable conditions.
