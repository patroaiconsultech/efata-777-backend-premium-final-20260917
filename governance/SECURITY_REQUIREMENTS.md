# SECURITY REQUIREMENTS FOR THE GITHUB REPOSITORY

The package cannot configure repository settings by itself. The human repository owner must verify:

- default branch protection enabled;
- pull request required;
- at least one independent human review required;
- force-push disabled on protected branch;
- secret scanning enabled where the GitHub plan supports it;
- push protection enabled where supported;
- dependency scanning/Dependabot enabled where applicable;
- SAST/code scanning enabled where supported;
- no deployment environment is triggered from this proposal branch;
- no repository secret is added to make the local fake tests pass.

The V2 implementation itself is Python-stdlib based; no third-party Python dependency is declared by this package.
