# (c) 2012-2015 Continuum Analytics, Inc. / http://continuum.io
# All Rights Reserved
#
# conda is distributed under the terms of the BSD 3-clause license.
# Consult LICENSE.txt or http://opensource.org/licenses/BSD-3-Clause.
from __future__ import print_function, division, absolute_import

import hashlib
import os
import requests
import shutil
import sys
import tempfile
import warnings
from logging import getLogger
from os.path import basename, dirname, join

from .config import ssl_verify
from .connection import CondaSession, RETRIES, handle_proxy_407
from .install import add_cached_package, find_new_location
from .lock import Locked
from .index import fetch as fetch_index, cache_fn_url

# To shut up pyflakes
fetch_index_ = fetch_index
log = getLogger(__name__)
dotlog = getLogger('dotupdate')
stdoutlog = getLogger('stdoutlog')
stderrlog = getLogger('stderrlog')

fail_unknown_host = False


def fetch_pkg(info, dst_dir=None, session=None):
    '''
    fetch a package given by `info` and store it into `dst_dir`
    '''

    session = session or CondaSession()

    fn = info['fn']
    url = info.get('url')
    if url is None:
        url = info['channel'] + '/' + fn
    log.debug("url=%r" % url)
    if dst_dir is None:
        dst_dir = find_new_location(fn[:-8])[0]
    path = join(dst_dir, fn)

    download(url, path, session=session, md5=info['md5'], urlstxt=True)
    if info.get('sig'):
        from .signature import verify, SignatureError

        fn2 = fn + '.sig'
        url = (info['channel'] if info['sig'] == '.' else
               info['sig'].rstrip('/')) + '/' + fn2
        log.debug("signature url=%r" % url)
        download(url, join(dst_dir, fn2), session=session)
        try:
            if verify(path):
                return
        except SignatureError as e:
            sys.exit(str(e))
        sys.exit("Error: Signature for '%s' is invalid." % (basename(path)))


def download(url, dst_path, session=None, md5=None, urlstxt=False,
             retries=None):
    pp = dst_path + '.part'
    dst_dir = dirname(dst_path)
    session = session or CondaSession()

    if not ssl_verify:
        try:
            from requests.packages.urllib3.connectionpool import InsecureRequestWarning
        except ImportError:
            pass
        else:
            warnings.simplefilter('ignore', InsecureRequestWarning)

    if retries is None:
        retries = RETRIES
    with Locked(dst_dir):
        try:
            resp = session.get(url, stream=True, proxies=session.proxies)
            resp.raise_for_status()
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 407:  # Proxy Authentication Required
                handle_proxy_407(url, session)
                # Try again
                return download(url, dst_path, session=session, md5=md5,
                                urlstxt=urlstxt, retries=retries)
            msg = "HTTPError: %s: %s\n" % (e, url)
            log.debug(msg)
            raise RuntimeError(msg)

        except requests.exceptions.ConnectionError as e:
            # requests isn't so nice here. For whatever reason, https gives
            # this error and http gives the above error. Also, there is no
            # status_code attribute here.  We have to just check if it looks
            # like 407.
            # See: https://github.com/kennethreitz/requests/issues/2061.
            if "407" in str(e):  # Proxy Authentication Required
                handle_proxy_407(url, session)
                # try again
                return download(url, dst_path, session=session, md5=md5,
                                urlstxt=urlstxt, retries=retries)
            msg = "Connection error: %s: %s\n" % (e, url)
            stderrlog.info('Could not connect to %s\n' % url)
            log.debug(msg)
            raise RuntimeError(msg)

        except IOError as e:
            raise RuntimeError("Could not open '%s': %s" % (url, e))

        size = resp.headers.get('Content-Length')
        if size:
            size = int(size)
            fn = basename(dst_path)
            getLogger('fetch.start').info((fn[:14], size))

        n = 0
        if md5:
            h = hashlib.new('md5')
        try:
            with open(pp, 'wb') as fo:
                more = True
                while more:
                    # Use resp.raw so that requests doesn't decode gz files
                    chunk = resp.raw.read(2**14)
                    if not chunk:
                        more = False
                    try:
                        fo.write(chunk)
                    except IOError:
                        raise RuntimeError("Failed to write to %r." % pp)
                    if md5:
                        h.update(chunk)
                    # update n with actual bytes read
                    n = resp.raw.tell()
                    if size and 0 <= n <= size:
                        getLogger('fetch.update').info(n)
        except IOError as e:
            if e.errno == 104 and retries:  # Connection reset by pee
                # try again
                log.debug("%s, trying again" % e)
                return download(url, dst_path, session=session, md5=md5,
                                urlstxt=urlstxt, retries=retries - 1)
            raise RuntimeError("Could not open %r for writing (%s)." % (pp, e))

        if size:
            getLogger('fetch.stop').info(None)

        if md5 and h.hexdigest() != md5:
            if retries:
                # try again
                log.debug("MD5 sums mismatch for download: %s (%s != %s), "
                          "trying again" % (url, h.hexdigest(), md5))
                return download(url, dst_path, session=session, md5=md5,
                                urlstxt=urlstxt, retries=retries - 1)
            raise RuntimeError("MD5 sums mismatch for download: %s (%s != %s)"
                               % (url, h.hexdigest(), md5))

        try:
            os.rename(pp, dst_path)
        except OSError as e:
            raise RuntimeError("Could not rename %r to %r: %r" %
                               (pp, dst_path, e))

        if urlstxt:
            add_cached_package(dst_dir, url, overwrite=True, urlstxt=True)


class TmpDownload(object):
    """
    Context manager to handle downloads to a tempfile
    """
    def __init__(self, url, verbose=True):
        self.url = url
        self.verbose = verbose

    def __enter__(self):
        if '://' not in self.url:
            # if we provide the file itself, no tmp dir is created
            self.tmp_dir = None
            return self.url
        else:
            if self.verbose:
                from .console import setup_handlers
                setup_handlers()
            self.tmp_dir = tempfile.mkdtemp()
            dst = join(self.tmp_dir, basename(self.url))
            download(self.url, dst)
            return dst

    def __exit__(self, exc_type, exc_value, traceback):
        if self.tmp_dir:
            shutil.rmtree(self.tmp_dir)
