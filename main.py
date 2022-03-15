import os
from re import U
from time import sleep
import pandas as pd
from IDSOrchestrator import IDSOrchestrator
from CICFLowMeter import CICFlowMeter
from Model import Model
import csv

base_path = os.path.dirname(os.path.realpath(__file__))
models_directory_path = base_path + '/models/'
pcap_dir = base_path + '/data/pcaps'
csv_dir = base_path + '/data/ids_input/'

class Main:
	def __init__(self):
		self.kill_switch = False
		self.ids = IDSOrchestrator()

	def main(self):
		self.kill_switch = False
		self.ids = None

		try:
			while not self.kill_switch:
				u_input = input('IDS-Agent: ')

				if u_input == 'run':
					self.ids.start()
				
				elif u_input == 'see queue':
					if not self.ids: continue
					
					exit_queue = False
					try:
						while not exit_queue:
							print(self.ids.classify_pcap_thread_pool._work_queue.qsize())
							sleep(1)
					except KeyboardInterrupt:
						exit_queue = True

				
				elif u_input == 'submit':
					submit_ids = IDSOrchestrator()
					return_flag = False
					while not return_flag:
						pcap_path = input('Pcap path: ')

						if pcap_path == '': 
							continue

						if pcap_path == 'back':
							return_flag = True
							continue

						# if directory, submit pcaps within
						if os.path.isdir(pcap_path):
							for pcap in os.listdir(pcap_path):
								submit_ids.classify_pcap(pcap_path + pcap, print_output=True)
						
						# submit pcap
						submit_ids.classify_pcap(pcap_path, print_output=True)
							
					# pcap submission exited
					submit_ids.kill()

				elif u_input == 'kill':
					self.kill()

		except KeyboardInterrupt:
			print('\n-- KeyboardInterrupt --')
			self.kill()

	def kill(self):
		print('Exiting IDS...')

		if self.ids: self.ids.kill()
		self.kill_switch = True

	def report_metrics(self, model_path, pcap_path, csv_path, pcap_conversion_time, prediction_time):
		report_path = 'reports/indv_pcap_performance.csv'
		# if the report doesn't already exists, write the title row first
		if os.path.isfile(report_path):
			report_headers = None
		else:
			report_headers = [
				'model_path',
				'pcap_path',
				'csv_path',
				'pcap_filesize',
				'csv_filesize',
				'pcap_conversion_time',
				'prediction_time'
			]

		row = [
			model_path,
			pcap_path,
			csv_path,
			os.path.getsize(pcap_path),
			os.path.getsize(csv_path),
			pcap_conversion_time,
			prediction_time
		]

		with open(report_path, 'a') as f:
			writer = csv.writer(f)

			# if the report doesn't already exists, write the title row first
			if report_headers:
				writer.writerow(report_headers)

			writer.writerow(row)
	
if __name__ == '__main__':
	main = Main()
	main.main()