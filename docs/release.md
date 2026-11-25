# Releasing the relaygate image

The release workflow publishes a standalone, immutable relaygate image. It
does not deploy relaygate or call a cloud-provider workflow.

1. Merge the reviewed source and release-workflow changes to `main`.
2. From **Actions → Release relaygate image → Run workflow**, select `main`.
3. Supply a new `vMAJOR.MINOR.PATCH` OCI tag, the exact 40-character `main`
   commit as `source_sha`, and `publish-relaygate` as the confirmation.
4. Record the successful workflow URL, source commit and OCI index digest.

The workflow fails closed unless the dispatch names its own `main` commit and
the release tag is absent. It tests that exact commit, publishes Linux amd64
and arm64 images, embeds an SBOM and max-mode BuildKit provenance, creates a
GitHub build-provenance attestation, and verifies all three forms of evidence.

Verify the GitHub attestation independently with:

```sh
gh attestation verify \
  oci://ghcr.io/agentworkforce/relaygate@sha256:<digest> \
  --repo AgentWorkforce/relaygate
```

Consumers should pin the OCI index digest, not a mutable tag.
