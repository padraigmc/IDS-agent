import os
import threading
from datetime import datetime
from subprocess import Popen, PIPE

BASE_PATH = os.path.dirname(os.path.realpath(__file__))

class CaptureTraffic():
	def __init__(self, interface: str, output_dir: str, output_filesize: int):
		self.interface = interface
		self.output_dir = output_dir
		self.output_filesize = output_filesize
		self.process = None
		self.kill_switch = False

		print('Traffic capture module initialized...')

	def capture(self):
		while not self.kill_switch: # not self.kill.is_set():
			dumpcap_command = [
				'dumpcap',
				'-i', self.interface,
				'-w', self.output_dir + 'capture.pcap',
				'-b', 'filesize:' + str(self.output_filesize)
			]
			self.process = Popen(dumpcap_command, stdout=PIPE, stderr=PIPE)

			pcap_path = ''
			for output_line in iter(self.process.stderr.readline, b''):
				if self.kill_switch: break

				if os.path.isfile(pcap_path):
					yield pcap_path
				
				# get pcap path from stdout
				pcap_path = str(output_line).split(sep=': ')[-1].replace('\\n\'', '')
		
	def kill(self):
		self.kill_switch = True
		if self.process:
			self.process.terminate()
