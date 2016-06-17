# (c) 2012-2015 Continuum Analytics, Inc. / http://continuum.io
# All Rights Reserved
#
# conda is distributed under the terms of the BSD 3-clause license.
# Consult LICENSE.txt or http://opensource.org/licenses/BSD-3-Clause.
from __future__ import print_function, division, absolute_import

import bz2
import hashlib
import json
import os
import requests
import sys
import warnings
from logging import getLogger
from os.path import join, isdir

from .compat import itervalues, iteritems, urlparse
from .config import (pkgs_dirs, DEFAULT_CHANNEL_ALIAS, remove_binstar_tokens,
                     hide_binstar_tokens, allowed_channels, add_pip_as_python_dependency,
                     ssl_verify, prioritize_channels, url_channel,
                     normalize_urls, get_channel_urls)
from .connection import CondaSession, handle_proxy_407
from .install import dist2pair, package_cache, linked_data, dist2filename

repodatas = {'@cache': {'packages': {}}}

dotlog = getLogger('dotupdate')
stdoutlog = getLogger('stdoutlog')
stderrlog = getLogger('stderrlog')

fail_unknown_host = False

def clear():
    repodatas.clear()
    repodatas['@cache'] = {'packages': {}}

def cache_dir():
    for pdir in pkgs_dirs:
        cache_dir = join(pdir, 'cache')
        if isdir(cache_dir):
            return cache_dir
    for pdir in pkgs_dirs:
        try:
            os.makedirs(cache_dir)
            return cache_dir
        except OSError:
            pass
    return join(pkgs_dirs[0], 'cache')


def cache_fn_url(url):
    md5 = hashlib.md5(url.encode('utf-8')).hexdigest()
    return '%s.json' % (md5[:8],)


def add_http_value_to_dict(resp, http_key, d, dict_key):
    value = resp.headers.get(http_key)
    if value:
        d[dict_key] = value

def clean_repodata(url, packages):
    channel, schannel = url_channel(url)
    prefix = schannel + '::' if schannel != 'defaults' else ''
    for fn, info in iteritems(packages or {}):
        fkey = prefix + fn
        info['fn'] = fn
        info['fkey'] = fkey
        info['dist'] = fkey[:-8]
        info['schannel'] = schannel
        info['channel'] = channel
        info['url'] = url + fn
        if (add_pip_as_python_dependency and
            info['name'] == 'python' and
            info['version'].startswith(('2.', '3.'))):  # noqa
            info.setdefault('depends', []).append('pip')


def fetch_repodata(url, url_b, use_cache=False, offline=False, session=None, silent=False):
    cache_path = join(cache_dir(), cache_fn_url(url))
    try:
        with open(cache_path) as f:
            cache = json.load(f)
    except (IOError, ValueError):
        cache = {'packages': {}}

    if use_cache or offline:
        if not use_cache and not silent:
            raise RuntimeError('Could not connect while offline: %s' % url_b)
        clean_repodata(url, cache.get('packages', {}))
        return cache

    if not ssl_verify:
        try:
            from requests.packages.urllib3.connectionpool import InsecureRequestWarning
        except ImportError:
            pass
        else:
            warnings.simplefilter('ignore', InsecureRequestWarning)

    session = session or CondaSession()

    headers = {}
    if "_etag" in cache:
        headers["If-None-Match"] = cache["_etag"]
    if "_mod" in cache:
        headers["If-Modified-Since"] = cache["_mod"]

    def fetch_(url):
        try:
            resp = session.get(url + 'repodata.json.bz2',
                               headers=headers, proxies=session.proxies)
            resp.raise_for_status()
            if resp.status_code == 304:
                return
            try:
                data = json.loads(bz2.decompress(resp.content).decode('utf-8'))
            except (IOError, ValueError):
                return 'Corrupt data found: %s' % url_b
            cache.clear()
            cache.update(data)
            add_http_value_to_dict(resp, 'Etag', cache, '_etag')
            add_http_value_to_dict(resp, 'Last-Modified', cache, '_mod')

        except ValueError as e:
            return "Invalid index file: %srepodata.json.bz2: %s" % (url_b, e)

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 407:  # Proxy Authentication Required
                handle_proxy_407(url, session)
                return fetch_(url)  # Try again
            elif e.response.status_code == 404:
                chan, user = url_channel(url)
                if chan != user:
                    netloc = urlparse.urlparse(url).netloc or 'Anaconda'
                    netloc = netloc.rsplit(':', 1)[0]
                    return 'Could not find %s user %s' % (netloc, user)
                elif not url.endswith('/noarch/'):  # noarch directory might not exist
                    return 'Could not find URL: %s' % url_b
            elif e.response.status_code == 403 and url.endswith('/noarch/'):
                pass
            elif e.response.status_code == 401 and url_b != url:
                msg = ("Warning: you may need to login to anaconda.org again with "
                       "'anaconda login' to access private packages(%s, %s)" %
                       (hide_binstar_tokens(url), e))
                stderrlog.info(msg)
                return fetch_(url_b)
            else:
                return "HTTPError: %s: %s\n" % (e, url_b)

        except requests.exceptions.SSLError as e:
            stderrlog.info("SSL verification error: %s\n" % e)

        except requests.exceptions.ConnectionError as e:
            # requests isn't so nice here. For whatever reason, https gives this
            # error and http gives the above error. Also, there is no status_code
            # attribute here. We have to just check if it looks like 407.  See
            # https://github.com/kennethreitz/requests/issues/2061.
            if "407" in str(e):  # Proxy Authentication Required
                handle_proxy_407(url, session)
                return fetch_(url)  # Try again
            return 'Could not connect to %s: %s\n' % (url_b, e)

    msg = fetch_(url)
    dotlog.debug("Fetching repodata: %s" % url)
    if msg is not None:
        if silent:
            return None
        raise RuntimeError(msg)

    cache = cache or {}
    packages = cache.setdefault('packages', {})
    cache['_url'] = url_b
    try:
        with open(cache_path, 'w') as fo:
            json.dump(cache, fo, indent=2, sort_keys=True)
    except IOError:
        pass
    clean_repodata(url, packages)
    return cache

def unknown_urls():
    pkgs = repodatas['@cache']['packages']
    for dist, info in iteritems(package_cache()):
        meta = None
        try:
            if info['dirs']:
                with open(join(info['dirs'][0], 'info', 'index.json')) as fi:
                    meta = json.load(fi)
        except IOError:
            pass
        if meta is None:
            if info['urls']:
                yield info['urls'].rsplit('/', 1)[0]
            continue
        schannel, dname = dist2pair(dist)
        fname = dname + '.tar.bz2'
        if info['urls']:
            url = info['urls'][0]
        elif 'url' in meta:
            url = meta['url']
        elif 'channel' in meta:
            url = meta['channel'].rstrip('/') + '/' + fname
        else:
            url = '<unknown>/' + fname
        channel_url, fname2 = url.rsplit('/', 1)
        channel, schannel2 = url_channel(url)
        if fname != fname2 or schannel != schannel2:
            continue
        meta.update({
            'fn': fname, 'dist': dist, 'fkey': dist + '.tar.bz2',
            'url': url, 'channel': channel, 'schannel': schannel})
        meta.setdefault('depends', [])
        pkgs[fname] = meta
        if not url.startswith('<unknown>/'):
            yield channel_url


def add_unknown(index):
    pkgs = repodatas['@cache']['packages']
    for dist, info in iteritems(package_cache()):
        fkey = dist + '.tar.bz2'
        fname = dist2filename(dist)
        if fkey not in index and fname in pkgs:
            dotlog.debug("adding cached pkg to index: %s" % fkey)
            index[fkey] = pkgs[fname].copy()


def prefix_urls(prefix):
    for dist, info in iteritems(linked_data(prefix)):
        yield info['url'].rsplit('/', 1)[0]


def add_prefix(index, prefix):
    for dist, info in iteritems(linked_data(prefix)):
        fn = info['fn']
        schannel = info['schannel']
        prefix = '' if schannel == 'defaults' else schannel + '::'
        key = prefix + fn
        if key in index:
            index[key] = index[key].copy()
            index[key]['link'] = info.get('link')
            continue
        url = info['url'].rsplit('/', 1)[0]
        if url in repodatas:
            info2 = repodatas[url]['packages'].get(fn, {})
            if info.get('schannel', None) == schannel:
                index[key] = info2.copy()
                index[key]['link'] = info.get('link')
            continue
        index[key] = info


def fetch(channel_urls, use_cache=False, offline=False):
    dotlog.debug('channel_urls=' + repr(channel_urls))
    # pool = ThreadPool(5)
    if allowed_channels:
        bad_urls = set(channel_urls) - set(allowed_channels)
        if bad_urls:
            sys.exit("""
Error: one or more requested channels are not in the allowed set:
  - %s
Allowed channels are:
  - %s
""" % ('\n  - '.join(bad_urls), '\n  - '.join(allowed_channels)))

    fetch_urls = {}
    result_urls = []
    for url in channel_urls:
        silent = url.startswith('?')
        url = url.lstrip('?').rstrip('/') + '/'
        url_b = remove_binstar_tokens(url)
        if url_b not in fetch_urls:
            fetch_urls[url_b] = (url, silent)
            result_urls.append(url_b)
        elif url_b in repodatas:
            fetch_urls[url_b] = None
        else:
            url2, silent2 = fetch_urls[url_b]
            # Use the tokenized name if one is given
            if url != url_b and url == url_b:
                url2 = url
            # Turn off silent if either requires it
            silent2 = silent and silent2
            fetch_urls[url_b] = (url2, silent2)

    try:
        import concurrent.futures
        executor = concurrent.futures.ThreadPoolExecutor(10)
    except (ImportError, RuntimeError):
        # concurrent.futures is only available in Python >= 3.2 or if futures is installed
        # RuntimeError is thrown if number of threads are limited by OS
        session = CondaSession()
        for url_b, parts in iteritems(fetch_urls):
            if parts:
                url, silent = parts
                repodata = fetch_repodata(url, url_b, use_cache=use_cache, offline=offline,
                                          session=session, silent=silent)
                if repodata:
                    repodatas[url_b] = repodata
    else:
        try:
            futures = []
            for url_b, parts in iteritems(fetch_urls):
                if parts:
                    url, silent = parts
                    session = CondaSession()
                    f = executor.submit(fetch_repodata, url, url_b, use_cache=use_cache,
                                        offline=offline, session=session, silent=silent)
                    futures.append((url_b, f))
            for url_b, f in futures:
                repodata = f.result()
                if repodata:
                    repodatas[url_b] = repodata
        finally:
            executor.shutdown(wait=True)

    index = {}
    for url in result_urls:
        packages = repodatas.get(url, {}).get('packages', {})
        index.update({info['fkey']: info.copy() for info in itervalues(packages)})
    return index


def get(channel_urls=(), prepend=True, platform=None,
        use_local=False, use_cache=False, unknown=False,
        offline=False, prefix=None):
    """
    Return the index of packages available on the channels

    If prepend=False, only the channels passed in as arguments are used.
    If platform=None, then the current platform is used.
    If prefix is supplied, then the packages installed in that prefix are added.
    """
    if use_local:
        channel_urls = ['local'] + list(channel_urls)
    channel_urls = normalize_urls(channel_urls, platform)
    if prepend:
        channel_urls.extend(get_channel_urls(platform, offline))
    if unknown:
        channel_urls.extend('?' + c for c in set(unknown_urls()))
    if prefix:
        channel_urls.extend('?' + c for c in set(prefix_urls(prefix)))

    stdoutlog.info("Fetching package metadata ...")
    index = fetch(channel_urls, use_cache=use_cache, offline=offline)
    if unknown:
        add_unknown(index)
    if prefix:
        add_prefix(index, prefix)
    stdoutlog.info("\n")

    channel_urls = [c.lstrip('?') for c in channel_urls]
    priorities = prioritize_channels(channel_urls)
    priorities = {p[0]: p[1] for p in itervalues(priorities)}
    maxp = max(itervalues(priorities)) + 1 if priorities else 1
    for info in itervalues(index):
        schannel = info['schannel']
        priority = priorities.get(schannel)
        if priority is None:
            priority = priorities[schannel] = maxp
            maxp += 1
        info['priority'] = priority
    return index

if __name__ == '__main__':
    import argparse
    import logging
    from .resolve import Resolve
    parser = argparse.ArgumentParser()
    parser.add_argument('--no-prepend', dest='prepend', action='store_false')
    parser.add_argument('--platform', action='store')
    parser.add_argument('--use-local', dest='use_local', action='store_true')
    parser.add_argument('--use-cache', dest='use_cache', action='store_true')
    parser.add_argument('--unknown', action='store_true')
    parser.add_argument('--offline', action='store_true')
    parser.add_argument('--prefix', action='store')
    parser.add_argument('--no-print', dest='do_print', action='store_false')
    parser.add_argument('channel_urls', nargs='*')
    parser.add_argument('--debug', action='store_true')
    args = vars(parser.parse_args())
    if args['debug']:
        logging.disable(logging.NOTSET)
        logging.basicConfig(level=logging.DEBUG)
    do_print = args['do_print']
    del args['debug']
    del args['do_print']
    index = get(**args)
    if do_print:
        r = Resolve(index, sort=True)
        for name in sorted(r.groups.keys()):
            if '@' not in name:
                print(name)
                for pkg in r.groups[name]:
                    info = r.index[pkg]
                    if info.get('schannel'):
                        print((' - %s: %s %s') % (info['fn'], info['schannel'], info['priority']))
