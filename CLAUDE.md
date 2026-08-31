# Instructions for AI Agents

This file provides guidance to AI assistants working on the Soundcore research project (Claude,
ChatGPT, Cursor, etc). It describes the tools available specifically for AI agents, the project's
permission systems, and pointers to other important documents.

## What This Project Is

This is a cybersecurity research project focused on understanding the over-the-air firmware upgrade
process of Soundcore P20i earbuds. For full information on the project's research goals and scope,
as well as the organization of this repository, see the `README.md` file.

## Code and Documentation Style

Before writing code or documentation for this project, you should read the `STYLE.md` file. It is
the primary style guide for both code and written prose.

## Ghidra MCP Server

One of the largest parts of this research project is firmware decompilation and reverse engineering.
The reverse engineering framework used is Ghidra (version `12.1.2_PUBLIC`), which has a model
context protocol (MCP) server set up for AI agents to access.

The MCP server is called `ghidra`. If you aren't able to connect to it, or can't open one of the
binaries you want to analyze, pause and ask the user to make the project available to you.

The Ghidra project is analyzing flat binaries that did not come with any symbols. As such, any
human-readable names (that don't follow Ghidra's `FUN_XXXXXXXX`/`DAT_XXXXXXXX` convention) have been
set by hand. These names *should* be treated with a grain of salt, and are not the absolute truth
regarding the purpose of a function. If you think a function's name is a misnomer, you **should**
bring it up with the user and recommend a change.

## Making Modifications

When making contributions, you can freely write to the `research/notes/` area that matches the
research plan you are working on, and you can freely read anything in the `research/` corpus. If you
want to modify other research files (past notes/plans, architecture documents, or vulnerability
reports), you **must** explain your intended changes to the user and obtain permission first.

When working in Ghidra, all your changes should be made through calls to the MCP server -- you
shouldn't be editing the raw Ghidra project files on disk. You may rename functions and data labels
that don't already have human-readable names, but you should ask the user before renaming a function
that already has an assigned name.

After making a contribution to the project, do **NOT** commit or push your changes to GitHub. Always
return control to the user so they can review the unstaged changes.

## Getting Help

While working on the project, you may come across something that you are unsure about. This could be
a contradiction, an ambiguity, something you think would be better done another way, or many other
sources of conflict. When you get confused, you should **always** pause and ask for clarification
rather than making a guess.
