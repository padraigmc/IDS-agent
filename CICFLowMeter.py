import os
from datetime import datetime
import time
from subprocess import Popen, PIPE
from concurrent.futures import ThreadPoolExecutor
from watchdog.observers import Observer
import watchdog.events

BASE_PATH = os.path.dirname(os.path.realpath(__file__))
CICFLOWMETER_PATH = BASE_PATH + '/tools/CICFlowMeter-4.0/bin/cfm'
CICFLOWMETER_BASE_DIR = BASE_PATH + '/tools/CICFlowMeter-4.0/bin/'
CSV_DIR = BASE_PATH + '/data/ids_input/'

STDOUT_LOG = "logs/CICFlowMeter_stdout.txt"
STDERR_LOG = "logs/CICFlowMeter_stderr.txt"

class CICFlowMeter:
	staticmethod
	def convert_pcap(pcap_path):
		# run CICFlowMeter batch script
		proc_start_time = time.time()
		process = Popen(
			['./cfm', pcap_path, CSV_DIR],
			cwd=CICFLOWMETER_BASE_DIR,
			stdout=PIPE,
			stderr=PIPE
		)

		stdout, stderr = process.communicate()
		proc_run_time = time.time() - proc_start_time
		
		if stderr == "b''": 
			print('CICFlowMeter error occured!')
			print(f'"{stderr}"')

		# write to output logs
		CICFlowMeter.std_log(stdout, stderr)

		return (CSV_DIR + os.path.basename(pcap_path) + '_Flow.csv', proc_run_time)

	@staticmethod
	def std_log(stdout, stderr):
		# write to output logs
		if stdout:
			with open(STDOUT_LOG, "a") as f:
				timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
				f.write(timestamp + ': ' + str(stdout) + '\n')

		if stderr:
			with open(STDERR_LOG, "a") as f:
				timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
				f.write(timestamp + ': ' + str(stderr) + '\n')
