# Third-party notices

The Go signer imports Tesla's [vehicle-command SDK](https://github.com/teslamotors/vehicle-command) at v0.4.1 (implementation pin 49977a18fd68567501d59e16a6c9e4a8b9348544). The SDK is Apache-2.0 licensed; its license is retained in third_party/vehicle-command-LICENSE. SDK source, vendor directories, compiled binaries and private build manifests are not bundled. signer/go.mod and signer/go.sum declare and checksum the dependencies. The wrapper is project integration code, separate from upstream SDK code.

Go resolves protobuf, saferith and golang-jwt modules under their upstream licenses. Optional Python live dependencies are PyJWT and cryptography, whose distributions include their own license terms. Preserve applicable dependency notices/licenses if redistributing compiled binaries or vendored source. This notice does not relicense original integration code; no project-wide license has been chosen.
