# TUI Mode

Running `scanr` with no subcommand launches the full-screen terminal UI.

```bash
scanr
```

## Behavior

- Enters alternate screen
- Enables raw mode
- Renders 3-panel layout
- Exits cleanly on `q`
- Restores terminal state on exit

Initial state:

- No scan starts automatically
- Empty overview is shown
- `Ctrl+S` starts scan

## Layout

- Header:
  - version
  - project path
  - scan status
  - key hints
- Left panel:
  - severity summary
  - risk level
- Right panel:
  - overview table
  - dependencies table
  - recommendations table

## Modes

- `Overview` (default)
- `Dependencies`
- `Recommendations`

## Key Bindings

- `Ctrl+S`: start scan
- `Ctrl+L`: dependencies view
- `Ctrl+R`: recommendations view
- `Esc`: close popup or return to overview
- `Up/Down`: move selection
- `Tab`: switch focus between severity and content panels
- `Enter`: toggle details popup
- `q`: quit

## Scan Status

- `Idle`
- `Scanning...`
- `Completed`
- `Failed: <message>`
