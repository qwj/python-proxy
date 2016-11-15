import time, sys, asyncio, functools

b2s = lambda i: '{:.1f}{}'.format(*((i/2**30,'G') if i>=2**30 else (i/2**20,'M') if i>=2**20 else (i/1024,'K')))
def all_stat(stats):
    cmd = sys.stdin.readline()
    if len(stats) <= 1:
        print('no traffic')
        return
    print('='*70)
    hstat = {}
    for remote_ip, v in stats.items():
        if remote_ip == 0: continue
        stat = [0]*6
        for host_name, v2 in v.items():
            for h in (stat, hstat.setdefault(host_name, [0]*6)):
                for i in range(6):
                    h[i] += v2[i]
        stat = [b2s(i) for i in stat[:4]] + stat[4:]
        print(remote_ip, '\tDIRECT: {4} ({0},{2})  PROXY: {5} ({1},{3})'.format(*stat))
    print(' '*3+'-'*64)
    hstat = sorted(hstat.items(), key=lambda x: sum(x[1]), reverse=True)[:15]
    hlen = max(map(lambda x: len(x[0]), hstat)) if hstat else 0
    for host_name, stat in hstat:
        stat, conn = (b2s(stat[0]+stat[1]), b2s(stat[2]+stat[3])), stat[4]+stat[5]
        print(host_name.ljust(hlen+5), '{0} / {1}'.format(*stat), '/ {}'.format(conn) if conn else '')
    print('='*70)

def realtime_stat(stats):
    history = [(stats[:4], time.time())]
    while True:
        yield from asyncio.sleep(1)
        history.append((stats[:4], time.time()))
        i0, t0, i1, t1 = history[0][0], history[0][1], history[-1][0], history[-1][1]
        stat = [b2s((i1[i]-i0[i])/(t1-t0))+'/s' for i in range(4)] + stats[4:]
        sys.stdout.write('DIRECT: {4} ({0},{2})   PROXY: {5} ({1},{3})\x1b[0K\r'.format(*stat))
        sys.stdout.flush()
        if len(history) >= 10:
            del history[:1]

def setup(loop, args):
    args.verbose = lambda s: sys.stdout.write(s+'\x1b[0K\n') and sys.stdout.flush()
    args.stats = {0: [0]*6}
    def modstat(remote_ip, host_name, stats=args.stats):
        host_name_2 = '.'.join(host_name.split('.')[-3 if host_name.endswith('.com.cn') else -2:]) if host_name.split('.')[-1].isalpha() else host_name
        tostat = (stats[0], stats.setdefault(remote_ip, {}).setdefault(host_name_2, [0]*6))
        return lambda i: lambda s: [st.__setitem__(i, st[i] + s) for st in tostat]
    args.modstat = modstat
    asyncio.async(realtime_stat(args.stats[0]))
    loop.add_reader(sys.stdin, functools.partial(all_stat, args.stats))


