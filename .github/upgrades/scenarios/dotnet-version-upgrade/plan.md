# .NET 10 Upgrade Plan

## Goal

Migrate the Sniffer WPF application and its packet-capture library from .NET Framework 4.7.2 to .NET 10 while preserving Windows desktop and capture behavior. Review and fix reproducible navigation, parsing, and capture-lifecycle defects.

## Confirmed decisions

- Target both projects in place as SDK-style `net10.0-windows`.
- Migrate from PcapDotNet to SharpPcap + PacketDotNet (approved by the user).
- Upgrade SnifferLib before its WPF consumer.
- Enable nullable reference types and resolve resulting diagnostics.
- Add focused regression tests; skip the optional generated baseline.
- Remain on `master`; commit only after validation succeeds.

## Execution order

1. **Migrate SnifferLib** — Convert the library project, add compatible package references, replace capture-device and packet parsing APIs, and extract/test pure packet-parsing behavior. Ensure ARP, IPv4, IPv6, malformed/truncated frames and non-IP Ethernet frames do not crash parsing.
2. **Migrate Sniffer WPF** — Convert the WPF project to SDK-style .NET 10 Windows, preserve XAML/resources/settings, update the project reference, and fix capture cancellation/restart/shutdown, packet navigation boundaries, nullability warnings, and UI thread updates without changing intended UX.
3. **Validate and secure** — Restore and build the full solution, run focused and existing tests, review dependency advisories, and perform a Windows UI/capture smoke test when an authorized adapter and Npcap are available. Record unavailable hardware checks accurately. Commit only after successful validation.

## Baseline and known risks

- The initial Release build fails because PcapDotNet assemblies are not present in the workspace; no tests were found.
- PcapDotNet 0.10.2 is incompatible with .NET 10 according to the generated assessment.
- Packet parsing currently dereferences IPv4 before checking Ethernet type, so ARP/IPv6/non-IP packets can fail.
- Go To excludes the final packet, Next can advance out of range, and capture stop uses unsupported `Thread.Abort`.
- The Windows capture smoke test requires Npcap and authorization to capture on the selected interface.
