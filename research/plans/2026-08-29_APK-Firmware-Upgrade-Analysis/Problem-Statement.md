# Problem Statement: APK Firmware Upgrade Analysis

This is the first research session for the Soundcore security project. The current long-term goal is to reverse engineer the firmware upgrade process for the P20i earbuds, which requires obtaining the latest version of their firmware for analysis. This research session has two primary goals.

## Goal 1: Understand APK Structure

Research should begin by understanding the structure of the Soundcore app APK in a high level of detail. It appears to be a Flutter app, and thus the decompiled Java
code is minimal (it's mostly just a wrapper around the `libapp.so` native binary).

This part of the session should answer the following questions before continuing:

1. How is the APK structured?
2. Where does the main app code live (`libapp` or somewhere else)?
3. What is the best approach for analysis of the main app code (JADX, Ghidra, another tool)?

Once the app's structure is understood and a plan is formed for how to easily analyze the app code, the session can proceed with the second goal.

## Goal 2: Understand Firmware Upgrade API

After the app is prepared for analysis, the first target is understanding how the app downloads firmware images to send to headphones over Bluetooth. Presumably there is an API endpoint that fetches binaries from Soundcore's servers.

This part of the research session should deliver the following:

1. Determine how the app fetches firmware packages: what API endpoint, what credentials are needed, what are the request/response payload structures?
2. Are there any immediately obvious protections for firmware upgrades: is the package signed, is the package encrypted, are there separate header binary blobs?
3. If possible, download the firmware for the Soundcore P20i earbuds.
