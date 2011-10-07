#******************************************************************************
# Copyright (c) 2011 Trevor Harwell
# All rights reserved. This program and the accompanying materials
# are made available under the terms of the Eclipse Public License v1.0
# which accompanies this distribution, and is available at
# http://www.eclipse.org/legal/epl-v10.html
#
# Contributors:
#	Trevor Harwell - initial implementations
#******************************************************************************


__version__ = '0.0.1'

import random
random.seed()
import urllib2
import urllib
import socket
import select
import time
import signal
import threading
import re
import plistlib
import os
import httplib

class TimeoutException(Exception):
	pass

ip_resolve = None
__all__ = ['AirFlick', 'findAppleTV', 'resolve_host', 'AirplayControl', 'AirFile', 'Youtube', 'Flickable']

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

class Flickable:
	pass		
	

class AirFile(Flickable):
	def __init__(self, file_path, local_ip = None, port="8199", tmp_folder="/tmp/airplay/"):
		if not os.path.isfile(file_path):
			temp = re.sub(r"\\", '', file_path)
			if not os.path.isfile(temp):
				raise Exception('File ' + str(file_path) + ' does not exist')
			else:
				self.file_path = temp
		else:
			self.file_path = file_path
		self.serve_file = self.random_name(self.file_path)

		if not os.path.isdir(tmp_folder):
			os.mkdir(tmp_folder)
		self.serve_file_path = os.path.join('/tmp/airplay', self.serve_file)
		os.symlink(os.path.abspath(self.file_path), self.serve_file_path)

		self.local_ip = local_ip
		self.port = port
		self.local_ips = list()
		if self.local_ip is None:
			self.get_local_ips()
		self.server = None
		self.start()

	def getURL(self):
		if self.local_ip is None or len(self.local_ip) < 1:
			self.get_local_ips()
			if len(self.local_ips) < 1:
				raise Exception("No local ips found")
			else:
				self.local_ip = self.local_ips[0]

		url = "http://" + str(self.local_ip).strip() + ":" + str(self.port).strip() + "/" + self.serve_file.strip()
		return url

	def start(self):
		import mongoose
		self.server = mongoose.Mongoose(None, listening_ports=self.port, enable_directory_listing='no', document_root=os.path.dirname(self.serve_file_path))

	def get_local_ips(self):
		self.local_ips = [ip for ip in socket.gethostbyname_ex(socket.gethostname())[2] if not ip.startswith("127.")]
		if len(self.local_ips) == 1:
			self.local_ip = self.local_ips[0]

	def random_name(self, f):
		l = "ABCDEFGHIJKLMNOPQRSTUVWXYZ123456789"
		final = ""
		for x in range(0, 8):
			final += random.choice(l)
		final += "-"
		for x in range(0, 4):
			final += random.choice(l)
		final += "-"
		for x in range(0, 4):
			final += random.choice(l)
		final += "-"
		for x in range(0, 4):
			final += random.choice(l)
		final += "-"
		for x in range(0, 12):
			final += random.choice(l)
		ext = ""
		try:
			ext = os.path.splitext(os.path.basename(f))[1]
		except Exception:
			pass
		return final + ext

	def __del__(self):
		try:
			os.remove(self.serve_file_path)
		except Exception:
			pass
		del self.server

class NoneIP(Exception):
	pass


class AirplayControl(threading.Thread):
	def __init__(self, ip=None, port='7000', rate=0.00000):
		threading.Thread.__init__(self)
		self.ip = ip
		self.port = port
		self.rate = rate
		self._isPlaying = False
		self.duration = 0.0
		self.position = 0.0
		self.started = threading.Event()
		self.setDaemon(True)

	def update_info(self):
		#while not self._stop.isSet():
		try:
			p = self._playback_info()
			if p['duration'] > 0:
				self._isPlaying = True
				self.duration = p['duration']
			else:
				self._isPlaying = False
			self.position = p['position']	
			self.rate = p['rate']
		except Exception:
			pass
			#time.sleep(.5)
	def run(self):
		while self.started.isSet():
			self.update_info()
			time.sleep(1)

	def start(self):
		self.started.set()
		threading.Thread.start(self)
		
	def isRunning(self):
		return self.started.isSet()
	
	def cancel(self):
		self.started.clear()

	def __del__(self):
		self.cancel()

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
		self._execute(data, post=True)

	def scrub(self, p):
		self.checkIP()
		if float(p) > float(self.duration) or float(p) < 0:
			raise Exception('Invalid scrub position')
		data = '/scrub?position=%######f' % round(p, 6)
		self._execute(data, post=True)

	def play(self):
		self.checkIP()
		self.rate = 1.00000
		data = '/rate?value=' + str(self.rate)
		self._execute(data, post=True)
		self._isPlaying = True

	def info(self):
		self.update_info()
		return self._playback_info()

	def _playback_info(self):
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

	def _flick(self, url, start='0.004067'):
		self.checkIP()
		if url is None or len(str(url)) < 1:
			raise Exception("Invalid URL: " + str(url))
		data = '/play'
		post = 'Content-Location: ' + url + '\nStart-Position:%######f\n' % round(float(start), 6)
		self._execute(data, post)
		time.sleep(.5)
		self.play()

	
	def _execute(self, data, post=False):
		self.checkIP()
		if post:
			if not isinstance(post, str):
				post = ''
		else:
			post = None
		req = urllib2.Request('http://' + str(self.ip) + ":" + str(self.port) + data, post)
		req.add_header('User-Agent', 'MediaControl/1.0')
		o = urllib2.build_opener(AirplayHTTPHandler)

		try:
			f = o.open(req)
			return f.read()
		except Exception, e:
			raise e
		
class Youtube(Flickable):	
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

	def getURL(self):
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
			if not lowest:
				return not_found['url']
			return lowest['url']
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
		self._atvs = []
		self.setDaemon(True)
		self.start()

	def __len__(self):
		return len(self._atvs)

	def run(self):
		import pybonjour
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
		import pybonjour
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
		import pybonjour
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
		import pybonjour
		if errorCode == pybonjour.kDNSServiceErr_NoError:
			atv = AppleTV(str(fullname), str(socket.inet_ntoa(rdata)))
			if atv not in self._atvs:
				self._atvs.append(atv)
			self.queried.append(True)
		return

	def __str__(self):
		temp = "["
		for i, item in list(enumerate(self._atvs, start=1)):
			if i is not len(self._atvs):
				temp += "%s, " % str(item)
			else:
				temp += str(item)
		temp += "]"
		return temp
	def __repr__(self):
		return str(self)

	def itervalues(self):
		l = list()
		for x in self._atvs:
			l.append(x.ip)
		return iter(l)
	def iteritems(self):
		l = list()
		for x in self._atvs:
			l.append((x.hostname, x.ip))
		return iter(l)
	def __iter__(self):
		return iter(self._atvs)

	def items(self):
		return self._atvs

	def iterkeys(self):
		return self.__iter__()

	def __getitem__(self, key):
		if isinstance(key, int):
			temp = self._atvs[key]
			#temp.start()
			return temp
		elif isinstance(key, str):
			for item in self._atvs:
				if key.lower() in str(item.ip).lower() or key.lower() in str(item.hostname).lower():
					#item.start()
					return item
		else:
			raise TypeError
		raise KeyError

	def __contains__(self, item):
		if isinstance(item, AppleTV):
			return (item in self._atvs)
		elif isinstance(item, str):
			for a in self._atvs:
				if item.lower() in str(a.ip).lower() or item.lower() in str(a.hostname).lower():
					return True
		else:
			raise TypeError
		return False

class AppleTV(AirplayControl):
	def __init__(self, hostname, ip):
		self.hostname = hostname
		self.ip = ip
		AirplayControl.__init__(self, self.ip)

	def flick(self, flick_object):
		if not self.started.isSet():
			self.start()
		if isinstance(flick_object, Flickable):
			url = None
			try:
				url = flick_object.getURL()
			except Exception:
				raise Exception("%s does not have getURL() interface method" % str(flick_object.__class__))
			if url is not None and isinstance(url, str) and len(url) > 0:
				self._flick(url)
			else:
				raise Exception("%s did not return a proper value from getURL() interface" % str(flick_object.__class__))
		elif isinstance(flick_object, str):
			self._flick(flick_object)
		else:
			raise TypeError

	def __repr__(self):
		temp = "('%s', '%s')" % (self.hostname, self.ip)
		return temp
	def __str__(self):
		return self.__repr__()
	def __eq__(self, item):
		if isinstance(item, AppleTV):
			return (self.hostname == item.hostname and self.ip == item.ip)
		else:
			return False
		

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
def is_valid_ip(ip):
	try:
		ip_sects = ip.split(".")
		if len(ip_sects) != 4:
			return False
		if len([sect for sect in ip_sects if int(sect) <= 255]) != 4:
			return False
		re_ip = re.search(r'[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}\.[\d]{1,3}', ip, re.I)
		if re_ip:
			return True
		return False
	except Exception:
		return False

class AirplayHTTPHandler(urllib2.HTTPHandler):
	def do_open(self, http_class, req):
		host = req.get_host()
		if not host:
			raise urllib2.URLError('no host given')
		h = http_class(host)
		h.set_debuglevel(self._debuglevel)

		headers = dict(req.headers)
		headers.update(req.unredirected_hdrs)
		
		try:
			h.request(req.get_method(), req.get_selector(), req.data, headers)
			r = h.getresponse()
		except socket.error, err:
			raise urllib2.URLError(err)
		r.recv = r.read
		fp = socket._fileobject(r, close=True)

		resp = urllib.addinfourl(fp, r.msg, req.get_full_url())
		resp.code = r.status
		resp.msg = r.reason
		return resp

	def do_request_(self, request):
		host = request.get_host()
		if not host:
		    raise urllib2.URLError('no host given')

		if request.has_data():  # POST
		    data = request.get_data()
		    if not request.has_header('Content-Length'):
			request.add_unredirected_header(
			    'Content-length', '%d' % len(data))

		sel_host = host
		if request.has_proxy():
		    scheme, sel = splittype(request.get_selector())
		    sel_host, sel_path = splithost(sel)

		#if not request.has_header('Host'):
		 #   request.add_unredirected_header('Host', sel_host)
		for name, value in self.parent.addheaders:
		    if not request.has_header(name):
			request.add_unredirected_header(name, value)
		request.timeout=10

		return request
			
