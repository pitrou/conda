from __future__ import print_function, division, absolute_import

from .resolve import Resolve
from .index import get as get_index

def get_package_versions(package, offline=False):
    index = get_index(offline=offline)
    r = Resolve(index)
    return r.get_pkgs(package, emptyok=True)
