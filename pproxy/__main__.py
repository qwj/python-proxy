if __package__ == '':
    import os, sys
    path = os.path.dirname(os.path.dirname(__file__))
    sys.path.insert(0, path)

if __name__ == '__main__':
    import pproxy
    pproxy.main()
