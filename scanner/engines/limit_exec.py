"""Trusted subprocess launcher; limits are set outside Flask's worker threads."""
import os
import resource
import sys

if __name__ == '__main__':
    resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64*1024*1024, 64*1024*1024))
    resource.setrlimit(resource.RLIMIT_CPU, (150, 150))
    # Tool-specific memory flags complement this Linux bound. macOS JVM address
    # reservations are not safely constrained by RLIMIT_AS.
    if sys.platform.startswith('linux'):
        resource.setrlimit(resource.RLIMIT_AS, (4*1024**3, 4*1024**3))
    os.execv(sys.argv[1], sys.argv[1:])
