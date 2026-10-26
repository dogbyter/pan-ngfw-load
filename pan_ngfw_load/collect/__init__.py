"""Live collector: read-only samples and log export via the PAN-OS XML API.

Data is written below <data_dir>/devices/<name>/ (see core.py) so that pan-ngfw-load can
analyse it like a tech support file (see pan_ngfw_load/parsers/live.py).
"""
