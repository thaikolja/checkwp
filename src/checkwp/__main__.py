"""Allow running as `python -m checkwp`."""

import sys

from checkwp.cli import main

if __name__ == "__main__":
    sys.exit(main())
