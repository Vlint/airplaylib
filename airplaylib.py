__version__ = '0.0.1'


import urllib2
import urllib
import socket
import select
import time
import signal
import threading
import re
import plistlib
import pybonjour

class TimeoutException(Exception):
	pass

ip_resolve = None
__all__ = ['AirFlick', 'findAppleTV', 'resolve_host', 'AirplayControl']

def AirFlick(url, ip):
	if url is None or len(str(url)) < 1:
		raise Exception("Invalid URL: " + str(url))
	if ip is None or len(str(ip)) < 1:
		raise Exception("Invalid IP: " + str(ip))

	data = 'Content-Location: ' + url + '\nStart-Position:0.0000\n'
	req = urllib2.Request('http://' + ip + ':7000/play', data)
	try:
		f = urllib2.urlopen(req)
	except Exception, e:
		raise("Could not connect to ApppleTV: " + str(e))
	return

class ServerInfoPoll(threading.Thread):
	def __init__(self, parent):
		threading.Thread.__init__(self)
		self.parent = parent
		self.doRun = True

	def run(self):
		while self.doRun:
			try:
				p = self.parent.playback_info()
				if p['duration'] > 0:
					self.parent._isPlaying = True
					self.parent.duration = p['duration']
				else:
					self.parent._isPlaying = False
				self.parent.position = p['position']	
				self.parent.rate = p['rate']
			except Exception:
				pass
			time.sleep(.5)
	def stop(self):
		self.doRun = False
		self.join()	


class AirplayControl:
	class NoneIP(Exception):
		pass
			

	def __init__(self, ip=None, port='7000', rate=0.00000):
		self.ip = ip
		self.port = port
		self.rate = rate
		self._isPlaying = False
		self.infoPoll = ServerInfoPoll(self)
		self.infoPoll.start()
		self.duration = 0.0
		self.position = 0.0

	def __del__(self):
		self.infoPoll.stop()

	def flick(self, url):
		self.checkIP()
		if url is None or len(str(url)) < 1:
			raise Exception("Invalid URL given: ", str(url))
		data = 'Content-Location: ' + url + '\nStart-Position:0.0000\n'
		req = urllib2.Request('http://' + str(self.ip) + ':' + str(self.port) + '/play', data)
		try:
			f = urllib2.urlopen(req)
		except Exception, e:
			raise Exception("Could not connect to ApppleTV: " + str(e))
		else:
			self.rate = 1.00000
			self._isPlaying = True

	def isPlaying(self):
		return self._isPlaying

	def checkIP(self):
		if self.ip is None:
			raise NoneIP('No ip has been given')
	def pause(self):
		self.checkIP()
		if not self._isPlaying:
			return
		self.rate = 0.00000
		data = '/rate?value=' + str(self.rate)
		self._execute(data)

	def setRate(self, rate):
		if float(rate) == self.rate or float(rate) > 30 or float(rate) < -30:
			return
		data = '/rate?value=' + str(rate)
		self._execute(data)

	def scrub(self, p):
		if float(p) > self.duration or float(p) < 0:
			return
		data = '/scrub?position=' + str(p)
		print data
		self._execute(data)
	

	def play(self):
		self.checkIP()
		if self.rate >= 1:
			return
		self.rate = 1.00000
		data = '/rate?value=' + str(self.rate)
		self._execute(data)
		self._isPlaying = True

	def playback_info(self):
		self.checkIP()
		data = '/playback-info'	
		f = self._execute(data)
		p = plistlib.readPlistFromString(f)
		return p

	def stop(self):
		self.checkIP()
		self.rate = 1.00000	
		data = '/stop'
		self._execute(data)
		self._isPlaying = False
	
	def _execute(self, data):
		self.checkIP()
		req = urllib2.Request('http://' + str(self.ip) + ":" + str(self.port) + data)
		f = urllib2.urlopen(req)
		return f.read()
		
class Youtube:	
	def __init__(self, url):
		self.url = url
		self.formatList = list()
		self.get_page()
	
	def getMP4s(self):		
		if len(self.formatList) < 1:
			raise Exception("No format list present")
		urls = list()
		for f in self.formatList:
			try:
				if 'mp4' in f['type'].strip().lower():
					urls.append(f)
			except Exception, e:
				print e
				
		return urls
	def getAirplayURL(self):
		mp4_list = self.getMP4s()
		formats = {'1080': 0, '720': 1, 'hd' : 2, 'high': 3, 'medium' : 4, '480': 5, 'low' : 6}	
		if len(mp4_list) < 1:
			return None
		elif len(mp4_list) > 1:
			lowest_value = 10
			lowest = None
			not_found = None
			for f in mp4_list:
				found = False
				for k, v in formats.items():
					if k.lower() in f['quality'].lower():
						found = True
						if v < lowest_value:
							lowest_value = v
							lowest = f
				if not found:
					not_found = f
		else:
			return mp4_list[0]['url']
	
	def checkURL(self):
		re_is_youtube = re.search('^http[s]*://[\w\.]*youtube\.com.*', str(self.url).strip(), re.I | re.M | re.S)
		if not re_is_youtube:
			raise Exception("Not a valid youtube URL")

	def get_page(self):
		self.checkURL()
		request = urllib2.Request(self.url)
		#This is a hack to bypass mature content without logging in
		request.add_header("User-Agent",  "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)")

		f = None	
		try:
			f = urllib2.urlopen(request)
		except Exception, e:
			raise Exception("Could not load URL: " + str(e))

		if f is None:
			raise Exception("Could not load URL")

		ydata = f.read()

		#check to see which URL storing method the page is using
		re_fmt_url_map = re.search("""fmt_url_map["']\s*:\s*["']([^'"]*)["']""", ydata, re.I)
		re_url_encoded_fmt_stream_map = re.search("""url_encoded_fmt_stream_map["']\s*:\s*["']([^'"]*)["']""", ydata, re.I)

		if not (re_fmt_url_map or re_url_encoded_fmt_stream_map):
			raise Exception("Could not find video URL data")

		if re_fmt_url_map:
			fmt_url_map = re_fmt_url_map.group(1)
			try:
				self.fmt_url_map_decode(fmt_url_map)
			except Exception, e:
				raise Exception("Youtube must have changed their URL encoding scheme.  Please update software: " + str(e))
		elif re_url_encoded_fmt_stream_map:
			data = re_url_encoded_fmt_stream_map.group(1)
			try:
				self.fmt_stream_map_decode(data)
			except Exception, e:
				raise Exception("Youtube must have changed their URL encoding scheme.  Please update software: " + str(e))

	def fmt_stream_map_decode(self, data):
		fmt_stream = data.split(",")
		fmt_stream_list = [x.split("url=")[1] for x in fmt_stream]
		fmt_list = list()
		for s in fmt_stream_list:
			stream = urllib.unquote(s)
			stream = str(stream.decode("unicode_escape", "ignore"))
			fmt = dict()
			re_type = re.search("&type=([^&]*)", stream, re.I)
			re_quality = re.search("&quality=([^&]*)", stream, re.I)
			if re_type:
				fmt['type'] = urllib.unquote_plus(re_type.group(1))
			else:
				fmt['type'] = None
			if re_quality:
				fmt['quality'] = urllib.unquote_plus(re_quality.group(1))
			else:
				fmt['quality'] = None
			re_temp_stream = re.search('(.*?&quality=[^&]*)', stream, re.I)
			if re_temp_stream:
				stream = re_temp_stream.group(1)
			stream = urllib.unquote(stream)
				

			fmt['url'] = stream
			fmt_list.append(fmt)
		self.formatList = fmt_list
		return

	def fmt_url_map_decode(self, data):
		formats = {'37' : ['1080p', 'MP4'], '22':['720p', 'MP4'], '35':['480p', 'FLV'], '34':['360p', 'MP4'], '18':['360p', 'MP4'], '5':['240p', 'FLV']}
		fmt_maps = data.split(",")
		fmt_list = list()
		for fmt in fmt_maps:
			fmt_dict = dict()
			(code, url) = fmt.split("|")
			url = str(url.decode("unicode_escape", "ignore")).decode('string_escape')
			url = re.sub(r'\\(.)', r'\1', url)
			url = urllib.unquote_plus(url)
			try:
				fmt_dict['type'] = formats[code.strip()][1]
				fmt_dict['quality'] = formats[code.strip()][0]
			except Exception:
				pass
			fmt_dict['url'] = url
			fmt_list.append(fmt_dict)
		self.formatList = fmt_list



class findAppleTV(threading.Thread):
	import pybonjour
	def __init__(self):
		threading.Thread.__init__(self)
		self.resolved = []
		self.queried = []
		self.atvs = []
		self.setDaemon(True)
		self.start()

	def __len__(self):
		return len(self.atvs)

	def run(self):
		timeout = 5
		service_name = "_airplay._tcp"
		browse_sdRef = pybonjour.DNSServiceBrowse(regtype = service_name, callBack = self.browse_callback)
		try:
			try:
				start_time = time.time()
				while True:
					#signal.alarm(2)
					#signal.signal(signal.SIGALRM, self.timeout_handler)
					try:
						ready = select.select([browse_sdRef], [], [])
						if browse_sdRef in ready[0]:
							pybonjour.DNSServiceProcessResult(browse_sdRef)
					except TimeoutException:
						pass
					finally:
					#	signal.alarm(0)
						pass
					diff = time.time() - start_time
					if diff > 1:
						break
			except:
				pass
		finally:
			browse_sdRef.close()

	def timeout_handler(self, signum, frame):
		raise TimeoutException

		
	def resolve_callback(self, sdRef, flags, interfaceIndex, errorCode, fullname, hosttarget, port, txtRecord):
		timeout = 5
		if errorCode != pybonjour.kDNSServiceErr_NoError:
			return
		query_sdRef = pybonjour.DNSServiceQueryRecord(interfaceIndex = interfaceIndex, fullname = hosttarget, rrtype = pybonjour.kDNSServiceType_A, callBack = self.query_record_callback)
		try:
			while not self.queried:
				ready = select.select([query_sdRef], [], [], timeout)
				if query_sdRef not in ready[0]:
					break
				pybonjour.DNSServiceProcessResult(query_sdRef)
			else:
				self.queried.pop()
		finally:
			query_sdRef.close()
		self.resolved.append(True)

	def browse_callback(self, sdRef, flags, interfaceIndex, errorCode, serviceName, regtype, replyDomain):
		timeout = 5
		if errorCode != pybonjour.kDNSServiceErr_NoError:
			return
		if not (flags & pybonjour.kDNSServiceFlagsAdd):
			return
		resolve_sdRef = pybonjour.DNSServiceResolve(0, interfaceIndex, serviceName, regtype, replyDomain, self.resolve_callback)	
		try:
			while not self.resolved:
				ready = select.select([resolve_sdRef], [], [], timeout)
				if resolve_sdRef not in ready[0]:
					break
				pybonjour.DNSServiceProcessResult(resolve_sdRef)
			else:
				self.resolved.pop()
			
		finally:
			resolve_sdRef.close()
		return 

	def query_record_callback(self, sdRef, flags, interfaceIndex, errorCode, fullname, rrtype, rrclass, rdata, ttl):
		if errorCode == pybonjour.kDNSServiceErr_NoError:
			atv = AppleTV(fullname, socket.inet_ntoa(rdata))
			if atv not in self.atvs:
				self.atvs.append(atv)
			self.queried.append(True)
		return
class AppleTV:
	def __init__(self, hostname, ip):
		self.hostname = hostname
		self.ip = ip

def query_host_callback(sdREf, flags, interfaceIndex, errorCode, fullname, rrtype, rrclass, rdata, ttl):
	import pybonjour
	if errorCode == pybonjour.kDNSServiceErr_NoError:
		ip = socket.inet_ntoa(rdata)
		global ip_resolve
		if ip_resolve is None:
			ip_resolve = ip

def resolve_host_timeout_handler(signum, frame):
	raise TimeoutException("No host found by that name")

def resolve_host(host, timeout=10):
	import pybonjour	
	global ip_resolve
	ip_resolve = None
	ip_addr = None
	query_sdRef = pybonjour.DNSServiceQueryRecord(fullname = host, rrtype = pybonjour.kDNSServiceType_A, callBack = query_host_callback)
	try:
		start_time = time.time()
		signal.alarm(timeout)
		signal.signal(signal.SIGALRM, resolve_host_timeout_handler)
		while not ip_resolve:
			ready = select.select([query_sdRef], [], [], 5)
			if query_sdRef not in ready[0]:
				continue
			else:
				pybonjour.DNSServiceProcessResult(query_sdRef)
			diff = time.time() - start_time

		else:
			ip_addr = ip_resolve
			ip_resolve = None
		signal.alarm(0)
			
	finally:
		query_sdRef.close()
	return ip_addr

