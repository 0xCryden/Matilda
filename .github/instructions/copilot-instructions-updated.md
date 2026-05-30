# Copilot instructions for Matilda (packet capture/replay)

This file combines repository-specific build/run notes and coding conventions to help Copilot-based sessions assist safely and effectively.

---

## Quick build & run (Windows / Visual Studio)

- Open Matilda.sln in Visual Studio 2022 (or newer). Select Platform: x64 and Configuration: Release or Debug, then Build Solution.
- Command-line (MSBuild):
  - Build solution: msbuild Matilda.sln /p:Configuration=Release /p:Platform=x64
  - Build project only: msbuild Matilda\Matilda.vcxproj /p:Configuration=Release /p:Platform=x64
- Run binary: Matilda\x64\Release\Matilda.exe (or the corresponding Debug path).

Notes: The repository provides prebuilt libs under lib\ (Pcap++.lib, Packet.lib, etc.). Ensure Npcap/WinPcap is installed on the host before running captures.

---

## Tests & lint

- There is no automated test suite or linter configured in this repo. Add CI, unit tests, or linters only after discussing with maintainers.

---

## High-level architecture

- MainApp (AppMain.*)
  - Windows GUI: main window, list view, packet detail (hex + parsed fields), device/process pickers.
  - Owns a Logger and CaptureManager instances and handles UI message dispatch.

- CaptureManager (CaptureManager.*)
  - Uses PcapPlusPlus (pcpp) to enumerate devices and perform live capture via PcapLiveDevice.
  - Stores captured frames in pcpp::RawPacketVector (m_capturedPackets) and parallel per-packet metadata in m_capturedMeta.
  - Posts batched UI notifications (WM_APP + 2) with lightweight arrays of summaries.
  - Provides APIs for: start/stop, getDeviceList, getCapturedCount, getCapturedPacketBytes, setFilter, sendCapturedPacketWithPayload.
  - Sending/replay requires capture to be running (device open): m_currentDevice is non-null while capturing.

- ConnectionTracker (ConnectionTracker.*)
  - Observes raw frames and maintains per-flow TCP sequence/ack state used for replay/offset calculations.

- Logger (Logger.*)
  - Appends messages to a log file and posts messages to the UI (WM_APP + 1). Post recipients are responsible for freeing any heap allocations passed via messages.

- External libs & artifacts
  - lib\ contains the PcapPlusPlus/Packet/lib dependencies expected by the project.
  - Generated build artifacts live under Matilda\x64\Release and Visual Studio metadata under .vs\ — avoid editing these generated files.

---

## Key repository-specific conventions

- Coding style (existing files):
  - One class per header/source pair (.h/.cpp); filenames should match class/type names.
  - Member variables use m_ prefix (e.g., m_running, m_capturedPackets).
  - Local (function-scoped) variables follow Hungarian-style notation in this codebase.
  - Types / classes use PascalCase.
  - Keep functions small (prefer < 50 lines) and split into helpers when needed.
  - Prefer small modules with single responsibility; keep side-effects at the system edge (main/adapters/controllers).
  - Use dependency injection for external concerns when practical.
  - Document intent/why for public APIs; do not duplicate trivial comments.

- UI/IPC conventions:
  - CaptureManager batches UI notifications and posts them with PostMessageA(WM_APP + 2, postCount, arr). The posted structure is allocated by the poster; message handlers must free strings and arrays as appropriate.
  - Logger posts strings to the UI with PostMessageA(WM_APP + 1, 0, new std::string(msg)). Receivers must delete the std::string pointer.

- Captured metadata ordering (capturedMeta)
  - When CaptureManager creates per-packet metadata it uses this exact order:
    [0] timestamp (HH:MM:SS.mmm)
    [1] direction ("Sent" | "Recv")
    [2] protocol ("TCP"|"UDP"|"OTHER")
    [3] src IP
    [4] src port (string)
    [5] dst IP
    [6] dst port (string)
    [7] length (string)
    [8] process name
  - Consumers rely on this ordering for ListView columns and replay logic.

- Threading & ownership
  - CaptureManager captures on a dedicated thread and synchronizes access to m_capturedPackets and m_capturedMeta using m_capturedLock.
  - UI callbacks / notifications may run on a different thread; preserve thread-safety when touching shared state.

- Error handling
  - Fail-fast: validate inputs early and return meaningful error strings where APIs accept an errOut parameter (e.g., sendCapturedPacketWithPayload).

---

## Existing Copilot instruction variants

The repo already contains opinionated variants:
- .github/copilot-instructions-strict.md
- .github/copilot-instructions-compact.md
- .github/copilot-instructions-strict-antisab.md

These contain stricter enforcement rules. Merge or reference them as needed; the canonical file should remain the single source that combines coding style and repository-specific operational notes.

---

## Where to look for maintenance tasks

- Core UI: AppMain.*
- Capture and replay logic: CaptureManager.*
- Connection sequence tracking: ConnectionTracker.*
- Logging: Logger.*
- Native dependencies: lib\ (prebuilt libs)

---

If further details (CI, tests, clang-tidy rules, or deeper architecture diagrams) are desired, indicate which area to expand.
