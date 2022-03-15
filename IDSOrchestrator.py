from CaptureTraffic import CaptureTraffic

from Model import Model

import os
import threading
from concurrent.futures import ThreadPoolExecutor
import csv
import os
from datetime import datetime


base_path = os.path.dirname(os.path.realpath(__file__))
models_directory_path = base_path + '/models/'
pcap_dir = base_path + '/data/pcaps/'
csv_dir = base_path + '/data/ids_input/'

network_interface = 'ens33'
pcap_size = 100

class IDSOrchestrator(threading.Thread):
	def __init__(self):
		super(IDSOrchestrator, self).__init__()
		self.model = Model()
		self.capture_traffic = None
		self.classify_pcap_thread_pool = ThreadPoolExecutor(thread_name_prefix='ids_classify_')
	
	def run(self):
		self.capture_traffic = CaptureTraffic(network_interface, pcap_dir, pcap_size)
		# capture network traffic
		for pcap_path in self.capture_traffic.capture():
			self.classify_pcap(pcap_path)

	def classify_pcap(self, pcap_path, print_output=False):
		# if file doesn't exists, return
		if not os.path.isfile(pcap_path) or not pcap_path.endswith('.pcap'):
			print(f'Invalid pcap path: {pcap_path}')
			return None

		# submit captured pcap to thread pool for classification
		self.classify_pcap_thread_pool.submit(self.model.classify_pcap, pcap_path, print_output)
		
	def kill(self):
		if self.capture_traffic:
			self.capture_traffic.kill()
			print('Traffic capture stopped...')

		self.classify_pcap_thread_pool.shutdown()
		print('Pcap conversion jobs stopped...')
