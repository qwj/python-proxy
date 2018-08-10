import os, sys, subprocess, struct

class MacSetting(object):
	def __init__(self, args):
		self.device = None
		self.listen = None
		self.modes = None
		self.mode_name = None
		for option in args.listen:
			protos = [x.name for x in option.protos]
			if option.unix or 'ssl' in protos or 'secure' in protos:
				continue
			if 'socks5' in protos:
				self.modes = ['setsocksfirewallproxy']
				self.mode_name = 'socks5'
				self.listen = option
				break
			if 'http' in protos:
				self.modes = ['setwebproxy', 'setsecurewebproxy']
				self.mode_name = 'http'
				self.listen = option
				break
		if self.listen is None:
			print('No server listen on localhost by http/socks5')
		ret = subprocess.check_output(['/usr/sbin/networksetup', '-listnetworkserviceorder']).decode()
		en0 = next(filter(lambda x: 'Device: en0' in x, ret.split('\n\n')), None)
		if en0 is None:
			print('Cannot find en0 device name!\n\nInfo:\n\n'+ret)
			return
		line = next(filter(lambda x: x.startswith('('), en0.split('\n')), None)
		if line is None:
			print('Cannot find en0 device name!\n\nInfo:\n\n'+ret)
			return
		self.device = line[3:].strip()
		for mode in self.modes:
			subprocess.check_call(['/usr/sbin/networksetup', mode, self.device, 'localhost', str(self.listen.port), 'off'])
		print(f'System proxy setting -> {self.mode_name} localhost:{self.listen.port}')
	def clear(self):
		if self.device is None:
			return
		for mode in self.modes:
			subprocess.check_call(['/usr/sbin/networksetup', mode+'state', self.device, 'off'])
		print('System proxy setting -> off')

class WindowsSetting(object):
	KEY = r'Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
	SUBKEY = 'DefaultConnectionSettings'
	def __init__(self, args):
		self.listen = None
		for option in args.listen:
			protos = [x.name for x in option.protos]
			if option.unix or 'ssl' in protos or 'secure' in protos:
				continue
			if 'http' in protos:
				self.listen = option
				break
		if self.listen is None:
			print('No server listen on localhost by http')
		import winreg
		key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.KEY, 0, winreg.KEY_ALL_ACCESS)
		value, regtype = winreg.QueryValueEx(key, self.SUBKEY)
		assert regtype == winreg.REG_BINARY
		server = f'localhost:{self.listen.port}'.encode()
		bypass = '<local>'.encode()
		counter = int.from_bytes(value[4:8], 'little') + 1
		value = value[:4] + struct.pack('<III', counter, 3, len(server)) + server + struct.pack('<I', len(bypass)) + bypass + b'\x00'*36
		winreg.SetValueEx(key, self.SUBKEY, None, regtype, value)
		winreg.CloseKey(key)
	def clear(self):
		if self.listen is None:
			return
		import winreg
		key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, self.KEY, 0, winreg.KEY_ALL_ACCESS)
		value, regtype = winreg.QueryValueEx(key, self.SUBKEY)
		assert regtype == winreg.REG_BINARY
		counter = int.from_bytes(value[4:8], 'little') + 1
		value = value[:4] + struct.pack('<II', counter, 1) + b'\x00'*44
		winreg.SetValueEx(key, self.SUBKEY, None, regtype, value)
		winreg.CloseKey(key)

def setup(args):
	if sys.platform == 'darwin':
		return MacSetting(args)
	elif sys.platform == 'win32':
		return WindowsSetting(args)
	else:
		print(f'System proxy setting: platform "{sys.platform}" not supported')
