"""Allow ``python -m src.capture`` to start the capture service."""

import sys

from src.capture.runner import main

sys.exit(main())
