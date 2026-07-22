"""Put the repository root on sys.path for the test session.

A couple of tests import the runnable ``examples/`` POC scripts to exercise the
exact code a user would run. ``examples`` is not an installed package, so this
makes it importable as a namespace package in any environment (local or CI),
independent of the current working directory.
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
