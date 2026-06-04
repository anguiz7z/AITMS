"""Optional vision-based diagram analyzer.

Only imported on demand; if `anthropic` is not installed or `ANTHROPIC_API_KEY`
is unset, the analyzer raises a clear error and the rest of ATMS continues to
work. Vision is a strict opt-in for users who have a key.
"""
