# 1. Command Pattern for CLI

Date: 2026-05-25

## Status

Accepted

## Context

Mobster exposes multiple CLI subcommands (generate, augment, upload, download, delete), each
requiring distinct logic for producing output and persisting it. A consistent structure is needed
to keep subcommand implementations uniform, testable, and easy to extend.

## Decision

All CLI subcommands implement the `Command` abstract base class defined in `src/mobster/cmd/base.py`.
Each command provides two async methods:

- `execute()` — performs the operation and stores the result internally
- `save()` — writes the result to disk or a remote destination

The CLI dispatcher in `main.py` calls both sequentially after `argparse` resolves the subcommand
to a `Command` subclass via `args.func`.

## Consequences

- Adding a new subcommand requires implementing `Command` and registering it in `cli.py` — a
  clear, low-friction extension point
- `execute()` and `save()` can be tested independently
- All commands are async, enabling concurrent operations (e.g. parallel uploads)
- The two-phase design couples output production to persistence, which may require workarounds
  if a command needs to stream output incrementally in the future
