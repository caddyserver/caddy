Init/Service Scripts
====================

This folder contains init/service scripts for using Caddy on various Linux and BSD distributions. They are created and maintained by the community.

## Getting Help

Different scripts have different maintainers; please consult the comments in the file and any README for assistance setting it up. Do not open an issue on the Caddy project about these scripts; instead, to ask a question or suggest a change, please contact the maintainer of the script directly.

## Disclaimer

The files contained herein are not officially supported by the Caddy project author and/or contributors, and as such, the files are not endorsed by the same. The Caddy project author and its contributors are not responsible for the function or malfunction of these scripts/files, or any unintended consequences to your system or website in attempting to set up Caddy. Users are expected to know how to administer their system, and these files should be considered as only a guide or suggestion for using Caddy in certain environments.

## Guidelines

The files distributed here should adhere to these principles where relevant (adjust accordingly for each system/platform):

- Don't run as root.
- Create a no-shell default user to run it.
- Raise file descriptor limits.
- Don't restart endlessly; if Caddy fails to start, there's a reason -- fix it, don't hammer it.
- Allow Caddy to re-use the same, persistent folder for storage.
- Stay as simple and minimal as possible.
- Be idempotent.
- Use comments to explain unexpected or unusual lines/patterns.
- Be secure by default.

Thank you for using Caddy! May it serve you well.
