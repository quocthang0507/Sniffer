# .NET 10 Upgrade Instructions

## Confirmed options

- Target framework: `net10.0`; use `net10.0-windows` for the WPF application if required by the Windows desktop framework.
- Flow mode: automatic. Preserve observable behavior and stop for a major dependency or architecture change that cannot be safely resolved within scope.
- Source-control branch: remain on the current `master` branch.
- Commit strategy: commit the completed work only after validation succeeds.
- Nullable reference types: enable and resolve resulting warnings in the migrated projects.
- Baseline: skip optional generated baseline; add focused regression tests for changed behavior.
- Capture backend: user approved replacing incompatible PcapDotNet with SharpPcap and PacketDotNet.

## Scope

- Upgrade both `Sniffer` and `SnifferLib` from .NET Framework 4.7.2 to .NET 10.
- Preserve the Windows WPF application and packet capture/parser behavior.
- Review source code and implement small, evidence-backed bug fixes directly related to navigation, packet parsing, and capture lifecycle.
- Add focused regression tests for changed behavior where practical.
- Use SharpPcap + PacketDotNet for capture and packet parsing; preserve existing behavior and explicitly document the Windows Npcap prerequisite.
- Build and run available tests; report unavailable hardware-dependent UI/capture checks accurately.
- Review dependency vulnerabilities after the upgrade and avoid unrelated refactoring.

## Environment and repository state

- Solution: `Sniffer.sln`
- Target: `.NET 10`
- Current branch at confirmation: `master`
- User-confirmed choice: do not create a working branch; commit at completion if validation succeeds.
- Do not install SDKs, drivers, or packages without the required approval.
- Baseline build currently fails because the repository is missing the PcapDotNet assemblies referenced by SnifferLib.
