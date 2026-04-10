"""Allow `python -m poam_generator` execution."""

import sys
from .cli import main

sys.exit(main())
