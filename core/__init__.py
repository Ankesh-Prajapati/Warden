import subprocess
import sys

# Extra subprocess.run() kwargs for every external tool call (7z, osslsigncode,
# readelf, ...). In the windowed desktop build there is no console, so Windows
# would otherwise flash a new console window for each child process.
NO_CONSOLE = {"creationflags": subprocess.CREATE_NO_WINDOW} if sys.platform == "win32" else {}
