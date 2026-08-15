"""Allow `python -m dnser` to invoke the CLI."""

import sys

from dnser.cli import main

sys.exit(main())
