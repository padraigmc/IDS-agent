import os
import threading
from datetime import datetime
from subprocess import Popen, PIPE

BASE_PATH = os.path.dirname(os.path.realpath(__file__))
DUMPCAP_PATH = BASE_PATH + '/tools/dumpcap/'


class CaptureTraffic(threading.Thread):
	def __init__(self, interface: str, output_file: str, output_filesize: int):
		threading.Thread.__init__(self)
		self.interface = interface
		self.output_file = output_file
		self.output_filesize = output_filesize
		self.process = None
		self.kill = threading.Event()

		print('Traffic capture module initialized...')

	def run(self):
		stdout = stderr = None

		print(self.kill.is_set())

		while not self.kill.is_set():
			self.process = Popen([
				'sudo',
				'/usr/bin/dumpcap',
				'-i', self.interface,
				'-w', self.output_file + 'capture.pcap',
				'-b', 'filesize:' + str(self.output_filesize)
			],
				cwd=DUMPCAP_PATH,
				stdout=PIPE,
				stderr=PIPE)

			print('dumpcap process started...')

			stdout, stderr = self.process.communicate()
			self.std_log(stdout, stderr)

			print('dumpcap communicate finished...')
		
	def stop(self):
		self.process.kill()
		self.kill.set()

	def std_log(self, stdout, stderr):
		# write to output logs
		if stdout:
			with open("logs/pcap_stdout.txt", "a") as f:
				timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
				f.write(timestamp + ': ' + str(stdout) + '\n')

		if stderr:
			with open("logs/pcap_stderr.txt", "a") as f:
				timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
				f.write(timestamp + ': ' + str(stderr) + '\n')

