from concurrent.futures import ThreadPoolExecutor
from os import path
from datetime import datetime
from subprocess import Popen, PIPE
from watchdog.observers import Observer
import watchdog.events

BASE_PATH = path.dirname(path.realpath(__file__))
CICFLOWMETER_BASE_PATH = BASE_PATH + '/tools/CICFlowMeter-4.0/bin/'

class PcapConverter:
	def __init__(self, pcap_dir, csv_dir):
		self.pcap_dir = pcap_dir
		self.csv_dir = csv_dir

		self.executor = ThreadPoolExecutor(thread_name_prefix='cicflowmeter_')

		# init watchdog file listener
		self.pcap_listener = watchdog.events.PatternMatchingEventHandler(
			patterns=["*.pcap"],
			ignore_patterns=[],
			ignore_directories=True
		)
		self.pcap_listener.on_created = self.on_created

		# create Watchdog observer and start
		self.observer = Observer()
		self.observer.schedule(self.pcap_listener, pcap_dir, recursive=False)
		self.observer.start()

		self.previous_pcap_path = None

		print('pcap file observer started...')

	def on_created(self, event):
		if self.previous_pcap_path:
			self.executor.submit(self.convert_pcap, self.previous_pcap_path)

		self.previous_pcap_path = event.src_path

	def convert_pcap(self, pcap_path):
		# run CICFlowMeter batch script
		process = Popen(
			["./cfm", pcap_path, self.csv_dir],
			cwd=CICFLOWMETER_BASE_PATH,
			stdout=PIPE,
			stderr=PIPE
		)

		stdout, stderr = process.communicate()

		# write to output logs
		self.std_log(stdout, stderr)

		print('CICFlowMeter module called...')

		return CICFLOWMETER_BASE_PATH + '/output/' + os.path.basename(pcap_path) + '_Flow.csv'

	def stop(self):
		self.observer.stop()
		self.observer.join()

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