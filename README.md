# IAM OPA integration

This repo contains the source code and a deployment Open Policy Agent (OPA) used as replacement of the INDIGO IAM Scope Policy engine.

Any commit to the `opa` directory will trigger a GitHub workflow which builds a bundle of _rego_ files for OPA.
The bundle is publicly available on the GitHub registry (`ghcr.io/indigo-iam/opa-iam:latest`).

The `doc` folder contains further documentation for this project, in particular:

- [Develop and test OPA policies](./doc/testing.md)
- [OPA configuration](./doc/configuration.md)