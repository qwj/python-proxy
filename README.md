python-proxy
===========

HTTP/Socks5/PSocks Asynchronous Proxy implemented in Python 3.6 asyncio with multiple useful features.

Overview
-----------

*Python 3.5* added new syntax *async def* and *await* to make asyncio programming easier. *Python 3.6* added new syntax *formatted string literals*. This utility is to demonstrate these new syntax and is also fully ready for production usage.

Features
-----------

- This utility can automatically detect incoming protocol from HTTP/Socks5/PSocks.
- Implemented basic authentication method for HTTP/Socks5/PSocks.
- Regex pattern file support for redirecting/blocking the incoming hosts.
- Stream cipher chacha20 support to communicate with remote server securely.
- Basic statistics for bandwidth and total traffic by client/hostname

Usage
-----------

    $ python3.6 pproxy.py -h
    usage: pproxy.py [-h] [-p PORT] [-t TYPES] [-a AUTH] [-c CIPHER] [-rs RSERVER]
                 [-rt RTYPE] [-ra RAUTH] [-rc RCIPHER] [-m MATCH] [-b BLOCK]
                 [-v]

    Proxy server that can tunnel by http,socks,psocks protocol.

    optional arguments:
      -h, --help   show this help message and exit
      -p PORT      listen port server bound to (default: 8080)
      -t TYPES     proxy server protocols (default: socks,http)
      -a AUTH      authentication requirement
      -c CIPHER    cipher key (default: no cipher)
      -rs RSERVER  remote server address (default: direct)
      -rt RTYPE    remote server type (default: psocks)
      -ra RAUTH    remote authorization code
      -rc RCIPHER  remote cipher key (default: no cipher)
      -m MATCH     match pattern file
      -b BLOCK     block pattern file
      -v           print verbose output

Examples
-----------

We can define file "rules" as follow:

    #google domains
    (?:.+\.)?google.*\.com
    (?:.+\.)?gstatic\.com
    (?:.+\.)?gmail\.com
    (?:.+\.)?ntp\.org
    (?:.+\.)?glpals\.com
    (?:.+\.)?akamai.*\.net
    (?:.+\.)?ggpht\.com
    (?:.+\.)?android\.com
    (?:.+\.)?gvt1\.com
    (?:.+\.)?youtube.*\.com
    (?:.+\.)?ytimg\.com
    (?:.+\.)?goo\.gl
    (?:.+\.)?youtu\.be
    (?:.+\.)?google\..+

Then start the pproxy.py

    python3.6 pproxy.py -rs aa.bb.cc.dd:8080 -rt http -m rules -v
    
With these parameters, this utility will serve incoming traffic by either http/socks5 protocol, redirect all google traffic to http proxy aa.bb.cc.dd:8080, and visit all other traffic locally.

To bridge two servers, add cipher key to ensure data can't be intercepted. First, run pproxy.py locally

    python3.6 pproxy.py -rs aa.bb.cc.dd:12345 -rt psocks -rc "This is a cipher key" -m rules -v
    
Next, run pproxy.py remotely on server "aa.bb.cc.dd"

    python3.6 pproxy.py -p 12345 -t psocks -rc "This is a cipher key"
    
By doing this, the traffic between local and aa.bb.cc.dd is encrypted by stream cipher Chacha20 with key "This is a cipher key". If target hostname is not in "rules", traffic will go through locally. Otherwise, traffic will go through the remote server by encryption.

