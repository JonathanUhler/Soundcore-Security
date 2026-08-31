# Soundcore Security

## Introduction

The goal of this project is to investigate the security of the firmware upgrade process on the
Soundcore P20i budget earbuds. Existing literature on Soundcore devices has found some security
flaws, but the P20i and the Jieli chip used them are relatively unresearched.

This project aims to reverse-engineer the firmware for the P20i and understand how firmware upgrades
are deployed over Bluetooth. Any issues found will be reported through Anker's responsible
disclosure platform.

## Getting Started

To get started working on the Soundcore research project, you should read the following documents in
order:

- Review this `README` file in its entirety to build an understanding of the project structure and
  research data organization practices.
- If you are an AI assistant, you must read `CLAUDE.md` (even if you aren't literally a Claude
  model) to understand the AI tools this project has, what you should and should not do without user
  permission, and more.
- Review the `STYLE.md` style guide to understand requirements for code and natural language.
- Read the `research/arch/` documents that are relevant to your research area to build an
  understanding of the latest research findings.
- Search the research corpus in `research/notes/`, based on keywords or concepts that you are
  actively investigating. Generally, corrections are added to research notes if old findings become
  outdated, although you should take very old notes with a grain of salt (confirm that they agree
  with the architecture documents before using their information).

## Available Hardware and Scope

This project owns a pair of P20i earbuds and can use them for dynamic testing. In addition, the
Soundcore mobile app for Android is available as a decompilation in the `./apk/` directory.

Research should remain scoped to the app, dynamic testing on owned hardware, and the Soundcore APIs.

## Project Structure

The project is structured into the following folders.

- `apk/`: Decompilation using JADX of the Soundcore app for Android.
- `research/`: See the next section for more information on how research data is organized.

## Research Process and Findings

As this project progresses, findings and notes are documented in the `research/` folder. Research
information consists of four sub-folders:

- `research/plans/`: Planning and speculation documents for things that (at the time of the docs
  being written) might be interesting to test. This area is where problem statement documents for
  other researchers or AI agents are placed. Plans are dated and given a name describing the scope
  or concept of the plan. They always contain a `Problem-Statement.md` document describing the goal
  of the research and a summary of (or cross-references to) supporting past research.
- `research/notes/`: As a research plan is executed, specific findings are written up in a
  corresponding notes area. Notes are dated with the date of the writeup and given the same name as
  the plan they correspond to, making it easy to determine which plans have been executed and what
  their direct findings where. Each notes section contains a `Summary.md` file describing any other
  files in the directory. Shorter research sessions may list all their approaches and findings in
  the summary document, while more complex sessions with several findings may create multiple
  markdown files with more info. The goal of research notes are to provide detailed information on
  exactly what was done and what was found as a result. Research notes might also have concluding
  ideas on future plans.
