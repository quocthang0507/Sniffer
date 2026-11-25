# Modernization Plan: .NET 10 and targeted quality improvements

**Project**: Sniffer

## Technical Framework

- **Language**: C#
- **Framework**: .NET Framework 4.7.2; Windows WPF application and library
- **Build**: Legacy MSBuild solution, `Sniffer.sln`; two projects
- **Key dependencies**: PcapDotNet 0.10.2, WinPcap, System.IO.Compression 4.3.0
- **Tests**: No test project was found in the repository inventory.

## Overview

Upgrade the existing Windows desktop application and library to .NET 10 while
preserving their packet-capture and UI behavior. Establish the existing
build/test baseline, resolve framework-related source incompatibilities, then
review and fix reproducible defects and make only small evidence-backed
improvements. Validate the changed behavior and inspect dependencies for known
vulnerabilities. No Azure migration or deployment is included.

## Migration Impact Summary

| Component | Current | Target | Notes |
|---|---|---|---|
| Sniffer | .NET Framework 4.7.2 WPF | .NET 10 Windows WPF | Preserve UI |
| SnifferLib | .NET Framework 4.7.2 | .NET 10 | Verify capture compatibility |

## Evidence and Risks

- Both project files use the legacy non-SDK format. The WPF project references
  SnifferLib. PcapDotNet references include `net40` binaries and an x86 core;
  compatibility with .NET 10 and the installed capture driver is unverified.
- `MainWindow.xaml.cs` uses `Thread.Abort`; replacing its unsupported behavior
  must preserve stop, restart, back, and shutdown semantics. The packet handler
  reads IPv4 before checking Ethernet type; investigate ARP, IPv6 and malformed
  frames with reproducible cases rather than assume the resulting behavior.
- Navigation conditions in `MainWindow.xaml.cs` exclude the final Go To index
  and permit Next beyond the last item; confirm and regression-test these.
- Only the .NET 11 SDK was observed on PATH. Establish whether a compatible
  .NET 10 SDK and Windows desktop runtime are available before execution;
  do not install software without approval.

## Validation and Decisions

Capture baseline build and available test results before edits; distinguish
pre-existing failures from regressions. Build the whole solution and run
existing tests plus focused regression tests for changed behavior after each
relevant task. Check WPF startup, capture start/stop/restart and navigation on
Windows when an authorized adapter and a compatible capture driver are
available. If unavailable, record the missing evidence rather than claim a
pass. Do not capture network traffic without authorization.

If capture compatibility requires replacing the library or driver, first
verify feasibility and preserve existing behavior; request user input before
any major dependency, behavioral or design decision. Likewise, flag any
substantial new functionality for approval rather than inventing it.
Dependency security fixes should use the smallest compatible patched versions;
document and seek approval for a major upgrade or broader scope.

The dependency-ordered executable task definitions are in
`.metadata/tasks.json`. This plan has not been executed.
