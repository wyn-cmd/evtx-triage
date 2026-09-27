# allows python -m evtx_triage, everything lives in cli.main

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
