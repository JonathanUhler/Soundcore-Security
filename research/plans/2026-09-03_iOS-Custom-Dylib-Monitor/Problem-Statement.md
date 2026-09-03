# Problem Statement: iOS Custom Dylib Monitor

The research notes at `research/notes/2026-09-01_iOS-Frida-Injection` document a process for
sideloading the Soundcore app onto a non-jailbroken iPhone, as well as injecting the Frida library
(although anti-debugger measures in the app detect Frida and prevent the app from launching).

The next session, `research/notes/2026-09-02_iOS-Anti-Tamper-Bypass`, attempted to work around
the anti-debugger logic through several iterations of Frida hooks, although none of them work as
intended.

The goal of this research session is to pursue an idea of creating a custom dynamic library (not
Frida) that will be added to the Soundcore app to monitor memory directly. This library will be
able to retrieve the values needed to access the Soundcore API from scripts rather than the app
itself.

`research/notes/2026-09-02_iOS-Anti-Tamper-Bypass/Pivot-To-Signing-Extraction.md` is the main
notes file that documents the new idea. Read that file to understand the limitations of Frida,
how the anti-debugger detection works at a high level based on Ghidra analysis, and the general
plan for the dynamic library monitor.

## Goal 1: Identify Injection Detection

The measure that could prevent a passive dynamic library from being injected and re-signed into
the Soundcore app would be a whitelist of which libraries are allowed to load. Analysis from the
last research session in Ghidra did not conclusively prove whether or not such a whitelist exists.

The first goal is to write and inject an extremely basic dynamic library. This library should
simply log that it was loaded successfully (e.g. "Hello world" to some log interface that can be
easily dumped/monitored). If the sideloaded Soundcore app runs without crashing and the log message
is recoverable, that proves no library whitelist exists.

## Goal 2: Create an Analyzer Library

If Goal 1 successfully demonstrates that custom libraries can be added and not trigger anti-debugger
measures, the next step is to write a library that extracts the values needed to call the Soundcore
API and download the P20i firmware.

There are two possible approaches for this. The one that's chosen will depend on the method of
retreiving data from the library, since the user-friendly Frida shell/debugger is not available.

1. Extract only the API credentials. This is the minimum information needed to call the API. If
   the values documented in prior research sessions that mapped the firmware ugprade API can be
   retreived from the app at runtime, the `scripts/probe_firmware_endpoint.py` script can be
   updated to call the API properly.
2. Download the firmware from the app. The ultimate goal is to get the P20i firmware image for
   analysis in Ghidra, not the API parameters. If it's easier to drive the API call from the
   dynamic library and extract the firmware binary from the iPhone, that's an alternative approach.
