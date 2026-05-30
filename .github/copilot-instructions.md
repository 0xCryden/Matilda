# Copilot Instructions for Matilda

## Purpose
Provide Copilot with repository-specific context for performing code changes in this C++ Win32 desktop packet-capture tool.

## Quick facts / prerequisites
- Platform: Windows (Win32 / x64). Visual Studio 2022 (v143) toolset expected.
- Dependencies: Npcap/WinPcap (runtime) and PcapPlusPlus (headers/libs). The project expects PcapPlusPlus headers at ..\PcapPlusPlus\* and prebuilt libs in ./lib.
- Solution: Matilda.sln and Matilda.vcxproj (Debug/Release, Win32 and x64).

## Build, run, and single-target commands
Use Visual Studio or the Developer Command Prompt.

- Build full solution (Release x64):
  msbuild Matilda.sln /p:Configuration=Release /p:Platform=x64

- Build single project (Matilda project):
  msbuild Matilda.vcxproj /p:Configuration=Debug /p:Platform=Win32

- From Visual Studio: open Matilda.sln and Build -> Build Solution or Build -> Build Matilda (select configuration/platform in the IDE).

- Run the built executable:
  bin path: ./x64/Release/Matilda.exe (or Matilda\Release\Matilda.exe depending on build output settings)

- Tests / lint: there are no unit tests or lint rules in repo. For static analysis use Visual Studio Code Analysis or run clang-tidy manually if added.

## High-level architecture (big picture)
- MainApp (AppMain.cpp / AppMain.h)
  - Win32 UI: creates windows, controls (ListView, Edit boxes, ComboBoxes, Buttons), and orchestrates user actions.
  - Instantiates Logger and CaptureManager, wires UI callbacks to capture operations, and receives UI updates via PostMessage / callbacks.

- CaptureManager (CaptureManager.h/.cpp)
  - Wrapper around PcapPlusPlus live capture (pcpp::PcapLiveDeviceList / PcapLiveDevice).
  - Runs a dedicated std::thread to receive packets, store them (pcpp::RawPacketVector), extract metadata (IP/port/protocol/time), and map flows to owning process using Windows GetExtendedTcpTable/GetExtendedUdpTable.
  - Batches notifications to the UI thread (PostMessage WM_APP + 2) to avoid flooding the UI.
  - API surface used by UI: start(callback, deviceIndex, uiWindow), stop(), getDeviceList(), setFilter(), sendCapturedPacket(index) and metadata accessors.

- Logger (Logger.h/.cpp)
  - Simple UI+file logger. Posts messages to the MainApp UI and writes to Matilda.log by default.

- Native bindings / libraries
  - PcapPlusPlus header usage: Packet.h, TcpLayer.h, UdpLayer.h, IPv4Layer.h, PcapLiveDevice.h and friends.
  - Linker dependencies listed in vcxproj: Pcap++.lib;Packet++.lib;Common++.lib;wpcap.lib;Ws2_32.lib;Iphlpapi.lib;Packet.lib

## Key repository conventions (repo-specific)
- One class per header/source pair; filenames should match the class name (already enforced by style).
- Member variables use m_ prefix (e.g., m_running, m_capturedPackets).
- UI messages: the capture thread communicates with UI either via a callback that writes to the Logger or by posting a WM_APP+2 message carrying a C-style array pointer; ownership and freeing of allocated memory must be respected.
- Packet data: stored in pcpp::RawPacketVector; metadata stored separately in m_capturedMeta under m_capturedLock.
- Process mapping: CaptureManager attempts to resolve PID -> executable name using QueryFullProcessImageNameA and Windows IP/TCP/UDP tables. Keep endian and address conversions consistent (inet_pton, ntohs, etc.).
- Device discovery: getDeviceList() uses pcpp::PcapLiveDeviceList::getInstance(); callers assume human-friendly description if available.
- Avoid committing large build artifacts and .vs/, Matilda\x64\* release folders. (Repo currently contains built artifacts; avoid re-adding them.)

## Notable files for change/guidance
- AppMain.cpp — high-level UI behavior, ListView formatting, control IDs.
- CaptureManager.* — capture concurrency, thread lifecycle, captured packet storage, mapping to processes.
- Logger.* — UI and file logging helper.
- Matilda.vcxproj — include/lib paths and platform configs (use this file as source of truth for build flags and libraries).

## When making changes (practical rules)
- Be conservative with threading changes; ensure join() and atomic flags are used to stop threads cleanly.
- When changing capture buffer structures, update both storage (m_capturedPackets/m_capturedMeta) and UI notification batching.
- If adding new third-party headers, update AdditionalIncludeDirectories in Matilda.vcxproj and add matching libs to ./lib or document how to build them.
- Prefer using the existing callback or PostMessage patterns for UI updates rather than invoking UI APIs directly from capture threads.

## Suggested improvements to repo (for maintainers)
- Move built artifacts out of repo and add a README with build prerequisites (Npcap, PcapPlusPlus clone/path, Visual Studio version).
- Add a simple CI build step (MSBuild) and optional clang-tidy/static analysis.

---

*This file augments the repository's existing guidance with Matilda-specific build steps, architecture notes, and conventions.*

- Order of top-level items: 1) License/header (if any), 2) Imports/includes: standard library, third-party, local (grouped and blank line between), 3) Constants/config, 4) Types/interfaces, 5) Private helpers, 6) Public functions/classes, 7) Exports/entry point.
- Naming: follow existing repository style; if none, prefer clear, descriptive names (camelCase for JS/TS, snake_case for Python, PascalCase for types/classes).
- Functions: keep functions < 50 lines when possible; prefer small helpers; aim for pure functions and explicit inputs/outputs.
- Error handling: validate inputs early and fail fast with clear errors; avoid swallowing exceptions silently.
- Comments & docs: comment the why, not the what. Document public APIs and modules.

## Architecture & Design
- Prefer small modules with a single responsibility.
- Define clear interfaces/abstractions at module boundaries.
- Use dependency injection for external concerns (I/O, network, DB) so logic is testable.
- Keep side-effects at the edges of the system (main, adapters, or controllers).

## Tests
- Add unit tests for new logic and edge cases.
- Use Arrange-Act-Assert structure in tests.
- Include integration tests where appropriate and document how to run them.

## Commits & PRs
- Write a short summary line, then a brief description of what, why, and how to test.
- Include related issue numbers.
- Add changelog note when behavior changes.

## Permissions & Actions
- Ask before running scripts, build, or tests that modify state or require external access.
- Do not modify files outside the repo root unless explicitly asked.

## If style is unclear
- Mirror existing code style and patterns in the repository.
- When in doubt, propose a short style decision in the PR and seek review.

## Example prompt for developer
"Please implement feature X in src\module: follow DRY and KISS, add unit tests, follow import ordering, and provide PR description and test steps. Ask before running any scripts."

---

*Generated by Copilot CLI instructions automation.*
