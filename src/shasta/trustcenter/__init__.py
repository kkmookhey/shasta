"""Trust center static page generator.

Generates a public-facing security trust page from existing scan data.
One command → one deployable index.html.
"""

from shasta.trustcenter.generator import generate_trust_center

__all__ = ["generate_trust_center"]
