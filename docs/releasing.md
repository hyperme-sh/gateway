# Releasing hypermesh-gateway

Releases for this service are container images, tagged with channel or version tags only. There is no Python package, wheel, or prepared-snapshot distribution.

- TEST uses the `:test` channel tag.
- Production uses a version tag, and the `:prod` channel tag as the moving alias. Production release tags in Azure Container Registry stay write-protected, as described in [FyberLabs/infra#959](https://github.com/FyberLabs/infra/issues/959).

Public container publication and the remaining Apache repositories are tracked in [FyberLabs/infra#993](https://github.com/FyberLabs/infra/issues/993).

Pull-request and `main` checks still build and test the source, including any clean-source or secret scan already in those jobs, and then discard temporary distribution files. They do not retain or publish package artifacts.

For the first container release, the declaration in `releases/candidate` names
the immutable Gateway image and the successful owner main build that qualified
it. Run `release-admission.yml` from main with the exact version to verify the
declaration and build before requesting the stable source tag. A subsequent
push of that tag repeats the read-only check.

Dispatch `release-publish.yml` on the authorized stable tag with the approved
OCI manifest digest. It repeats admission on that tag, verifies the image
revision and copies the manifest byte-for-byte to the GHCR version tag. An
existing matching tag can be verified again. Production ACR publication and
the production channel use the existing Infra ownership and require separate
authorization.
