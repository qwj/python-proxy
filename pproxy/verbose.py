import time, sys, asyncio, functools

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
        stat = [(f'{i/1024/1024/1024:.1f}G' if i>=1024*1024*1024 else (f'{i/1024/1024:.1f}M' if i>=1024*1024 else f'{i/1024:.1f}K')) for i in stat[:4]] + stat[4:]
        print(remote_ip, f'\tDIRECT: {stat[4]} ({stat[0]},{stat[2]})  PROXY: {stat[5]} ({stat[1]},{stat[3]})')
    print(' '*3+'-'*64)
    hstat = sorted(list(hstat.items()), key=lambda x: sum(x[1]), reverse=True)[:15]
    hlen = max(map(lambda x: len(x[0]), hstat)) if hstat else 0
    for host_name, stat in hstat:
        stat, conn = (stat[0]+stat[1], stat[2]+stat[3]), stat[4]+stat[5]
        stat = [(f'{i/1024/1024/1024:.1f}G' if i>=1024*1024*1024 else (f'{i/1024/1024:.1f}M' if i>=1024*1024 else f'{i/1024:.1f}K')) for i in stat]
        print(host_name.ljust(hlen+5), f'{stat[0]} / {stat[1]}', f'/ {conn}' if conn else '')
    print('='*70)

async def realtime_stat(stats):
    history = [(stats[:4], time.time())]
    while True:
        await asyncio.sleep(1)
        history.append((stats[:4], time.time()))
        i0, t0, i1, t1 = *history[0], *history[-1]
        stat = [(i1[i]-i0[i])/(t1-t0) for i in range(4)]
        stat = [(f'{i/1024/1024:.1f}M/s' if i>=1024*1024 else f'{i/1024:.1f}K/s') for i in stat]
        sys.stdout.write(f'DIRECT: {stats[4]} ({stat[0]},{stat[2]})   PROXY: {stats[5]} ({stat[1]},{stat[3]})\x1b[0K\r')
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
    loop.create_task(realtime_stat(args.stats[0]))
    loop.add_reader(sys.stdin, functools.partial(all_stat, args.stats))


