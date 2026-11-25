# Execution Tasks

1. **Migrate SnifferLib and packet capture**
   - Convert `SnifferLib.csproj` to SDK style and target `net10.0-windows`.
   - Replace PcapDotNet with SharpPcap and PacketDotNet.
   - Preserve interface selection and packet details; safely classify ARP, IPv4, IPv6, and unknown/truncated frames.
   - Add focused packet parser regression tests.

2. **Migrate WPF application and fix defects** (depends on task 1)
   - Convert `Sniffer.csproj` to SDK-style WPF targeting `net10.0-windows`; retain XAML, assets, settings, and app identity.
   - Replace `Thread.Abort` with cooperative capture cancellation and ensure stop/restart/back/shutdown are safe.
   - Fix first/last/previous/next/Go To boundaries and empty-list auto-scroll.
   - Enable nullable analysis and resolve warnings without broad unrelated refactoring.

3. **Validate, review dependencies, and commit** (depends on tasks 1 and 2)
   - Restore and build the solution; run all tests and focused regressions.
   - Review package vulnerabilities and resolve compatible findings.
   - Test WPF startup and capture lifecycle on Windows when Npcap and an authorized adapter are available.
   - Record environment limitations; commit only if validation succeeds.
