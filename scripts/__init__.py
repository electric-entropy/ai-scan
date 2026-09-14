"""Release-gate tooling for AI-Scan.

These modules are deliberately NOT part of the shipped ``ai_scan`` runtime
package. They are invoked by local release checks and the CI/package workflows
(``python -m scripts.<module>``) to enforce release gates before any artifact is
uploaded. Keeping them out of ``src/ai_scan`` keeps the runtime dependency and
attack surface minimal.
"""
