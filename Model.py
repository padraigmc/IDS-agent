import os
import ntpath
import time
import datetime as dt
from pandas import pandas as pd
import joblib
import warnings
import csv
from datetime import datetime
from CICFLowMeter import CICFlowMeter

base_dir = os.path.dirname(os.path.realpath(__file__))
models_directory_path = base_dir + '/models/'
maliciious_report_path = base_dir + '/reports/malicious_traffic.csv'

new_titles = {
	'Dst Port': 'Dst Port',
	'Protocol': 'Protocol',
	'Timestamp': 'Timestamp',
	'Flow Duration': 'Flow Duration',
	'Total Fwd Packet': 'Tot Fwd Pkts',
	'Total Bwd packets': 'Tot Bwd Pkts',
	'Total Length of Fwd Packet': 'TotLen Fwd Pkts',
	'Total Length of Bwd Packet': 'TotLen Bwd Pkts',
	'Fwd Packet Length Max': 'Fwd Pkt Len Min',
	'Fwd Packet Length Min': 'Fwd Pkt Len Mean',
	'Fwd Packet Length Mean': 'Fwd Pkt Len Max',
	'Fwd Packet Length Std': 'Fwd Pkt Len Std',
	'Bwd Packet Length Max': 'Bwd Pkt Len Max',
	'Bwd Packet Length Min': 'Bwd Pkt Len Min',
	'Bwd Packet Length Mean': 'Bwd Pkt Len Mean',
	'Bwd Packet Length Std': 'Bwd Pkt Len Std',
	'Flow Bytes/s': 'Flow Byts/s',
	'Flow Packets/s': 'Flow Pkts/s',
	'Flow IAT Mean': 'Flow IAT Mean',
	'Flow IAT Std': 'Flow IAT Std',
	'Flow IAT Max': 'Flow IAT Max',
	'Flow IAT Min': 'Flow IAT Min',
	'Fwd IAT Total': 'Fwd IAT Tot',
	'Fwd IAT Mean': 'Fwd IAT Mean',
	'Fwd IAT Std': 'Fwd IAT Std',
	'Fwd IAT Max': 'Fwd IAT Max',
	'Fwd IAT Min': 'Fwd IAT Min',
	'Bwd IAT Total': 'Bwd IAT Tot',
	'Bwd IAT Mean': 'Bwd IAT Mean',
	'Bwd IAT Std': 'Bwd IAT Std',
	'Bwd IAT Max': 'Bwd IAT Max',
	'Bwd IAT Min': 'Bwd IAT Min',
	'Fwd PSH Flags': 'Fwd PSH Flags',
	'Bwd PSH Flags': 'Bwd PSH Flags',
	'Fwd URG Flags': 'Fwd URG Flags',
	'Bwd URG Flags': 'Bwd URG Flags',
	'Fwd Header Length': 'Fwd Header Len',
	'Bwd Header Length': 'Bwd Header Len',
	'Fwd Packets/s': 'Fwd Pkts/s',
	'Bwd Packets/s': 'Bwd Pkts/s',
	'Packet Length Min': 'Pkt Len Min',
	'Packet Length Max': 'Pkt Len Max',
	'Packet Length Mean': 'Pkt Len Mean',
	'Packet Length Std': 'Pkt Len Std',
	'Packet Length Variance': 'Pkt Len Var',
	'FIN Flag Count': 'FIN Flag Cnt',
	'SYN Flag Count': 'SYN Flag Cnt',
	'RST Flag Count': 'RST Flag Cnt',
	'PSH Flag Count': 'PSH Flag Cnt',
	'ACK Flag Count': 'ACK Flag Cnt',
	'URG Flag Count': 'URG Flag Cnt',
	'CWR Flag Count': 'CWE Flag Count',
	'ECE Flag Count': 'ECE Flag Cnt',
	'Down/Up Ratio': 'Down/Up Ratio',
	'Average Packet Size': 'Pkt Size Avg',
	'Fwd Segment Size Avg': 'Fwd Seg Size Avg',
	'Bwd Segment Size Avg': 'Bwd Seg Size Avg',
	'Fwd Bytes/Bulk Avg': 'Fwd Byts/b Avg',
	'Fwd Packet/Bulk Avg': 'Fwd Pkts/b Avg',
	'Fwd Bulk Rate Avg': 'Fwd Blk Rate Avg',
	'Bwd Bytes/Bulk Avg': 'Bwd Byts/b Avg',
	'Bwd Packet/Bulk Avg': 'Bwd Pkts/b Avg',
	'Bwd Bulk Rate Avg': 'Bwd Blk Rate Avg',
	'Subflow Fwd Packets': 'Subflow Fwd Pkts',
	'Subflow Fwd Bytes': 'Subflow Fwd Byts',
	'Subflow Bwd Packets': 'Subflow Bwd Pkts',
	'Subflow Bwd Bytes': 'Subflow Bwd Byts',
	'FWD Init Win Bytes': 'Init Fwd Win Byts',
	'Bwd Init Win Bytes': 'Init Bwd Win Byts',
	'Fwd Act Data Pkts': 'Fwd Act Data Pkts',
	'Fwd Seg Size Min': 'Fwd Seg Size Min',
	'Active Mean': 'Active Mean',
	'Active Std': 'Active Std',
	'Active Max': 'Active Max',
	'Active Min': 'Active Min',
	'Idle Mean': 'Idle Mean',
	'Idle Std': 'Idle Std',
	'Idle Max': 'Idle Max',
	'Idle Min': 'Idle Min'
}
dataset_titles = [
    'Dst Port',
    'Protocol',
    'Timestamp',
    'Flow Duration',
    'Tot Fwd Pkts',
    'Tot Bwd Pkts',
    'TotLen Fwd Pkts',
    'TotLen Bwd Pkts',
    'Fwd Pkt Len Max',
    'Fwd Pkt Len Min',
    'Fwd Pkt Len Mean',
    'Fwd Pkt Len Std',
    'Bwd Pkt Len Max',
    'Bwd Pkt Len Min',
    'Bwd Pkt Len Mean',
    'Bwd Pkt Len Std',
    'Flow Byts/s',
    'Flow Pkts/s',
    'Flow IAT Mean',
    'Flow IAT Std',
    'Flow IAT Max',
    'Flow IAT Min',
    'Fwd IAT Tot',
    'Fwd IAT Mean',
    'Fwd IAT Std',
    'Fwd IAT Max',
    'Fwd IAT Min',
    'Bwd IAT Tot',
    'Bwd IAT Mean',
    'Bwd IAT Std',
    'Bwd IAT Max',
    'Bwd IAT Min',
    'Fwd PSH Flags',
    'Bwd PSH Flags',
    'Fwd URG Flags',
    'Bwd URG Flags',
    'Fwd Header Len',
    'Bwd Header Len',
    'Fwd Pkts/s',
    'Bwd Pkts/s',
    'Pkt Len Min',
    'Pkt Len Max',
    'Pkt Len Mean',
    'Pkt Len Std',
    'Pkt Len Var',
    'FIN Flag Cnt',
    'SYN Flag Cnt',
    'RST Flag Cnt',
    'PSH Flag Cnt',
    'ACK Flag Cnt',
    'URG Flag Cnt',
    'CWE Flag Count',
    'ECE Flag Cnt',
    'Down/Up Ratio',
    'Pkt Size Avg',
    'Fwd Seg Size Avg',
    'Bwd Seg Size Avg',
    'Fwd Byts/b Avg',
    'Fwd Pkts/b Avg',
    'Fwd Blk Rate Avg',
    'Bwd Byts/b Avg',
    'Bwd Pkts/b Avg',
    'Bwd Blk Rate Avg',
    'Subflow Fwd Pkts',
    'Subflow Fwd Byts',
    'Subflow Bwd Pkts',
    'Subflow Bwd Byts',
    'Init Fwd Win Byts',
    'Init Bwd Win Byts',
    'Fwd Act Data Pkts',
    'Fwd Seg Size Min',
    'Active Mean',
    'Active Std',
    'Active Max',
    'Active Min',
    'Idle Mean',
    'Idle Std',
    'Idle Max',
    'Idle Min'
]
malicious_labels = [
    'Brute Force -Web',
    'Brute Force -XSS',
    'Bot',
    'DDOS attack-HOIC',
    'DDoS attacks-LOIC-HTTP',
    'DDOS attack-LOIC-UDP',
    'DoS attacks-GoldenEye',
    'DoS attacks-Hulk',
    'DoS attacks-SlowHTTPTest',
    'DoS attacks-Slowloris',
    'FTP-BruteForce',
    'Infilteration',
    'SSH-Bruteforce',
    'SQL Injection'
  ]

class Model:
	def __init__(self):
		self.model_path = 'models/2022-03-05-140619_mlp_pipeline.pkl'

		# supress joblib version mismatch warning
		with warnings.catch_warnings():
			warnings.simplefilter("ignore")
			self.model_pipeline = joblib.load(self.model_path)
		
	def classify_pcap(self, pcap_path, print_output=False):
		csv_path, pcap_convert_time = CICFlowMeter.convert_pcap(pcap_path)
		if print_output: print(f'Converted pcap in {pcap_convert_time} seconds...')

		prediction_time = self.predict(csv_path)
		if print_output: print(f'Prediction made in {prediction_time} seconds...')

		self.report_metrics(self.model_path, pcap_path, csv_path, pcap_convert_time, prediction_time)

	def predict(self, csv_path, handle_pred=True):
		data = pd.read_csv(csv_path)
		data = self.transform_data(data)

		predict_start_time = time.time()
		prediction = self.model_pipeline.predict(data)
		predict_time = time.time() - predict_start_time

		if handle_pred:
			self.handle_prediction(prediction, data, csv_path)
		
		return predict_time
	
	def handle_prediction(self, pred, df, csv_path):
		result = ''
		malicious_detection = [label for label in pred if label != 'Benign']
		print(malicious_detection)
		# malicious classification
		if malicious_detection:
			result = 'Maliciuos'
			df['Label'] = pred

			# write new dataframe with malicious label to maliciuos dir and delete old csv
			df.to_csv('data/malicious/' + ntpath.basename(csv_path))

			with open(maliciious_report_path, 'a') as f:
				timstamp = datetime.now().strftime('%Y-%m-%d %H-%M-%S')
				writer = csv.writer(f)
				writer.writerow([timstamp, csv_path, len(malicious_detection)])

		else: # clean classifcation
			result = 'Clean'
			#print('Clean classification!')
	
	def transform_data(self, df):
		drop_cols = [
			'Flow ID',
			'Src IP',
			'Src Port',
			'Dst IP',
			'Label'
		]

		# remove columns not present in training set
		df = df.drop(labels=drop_cols, axis=1)
		df = df.rename(columns=new_titles)

		# convert 'Timestamp' feature to epoch
		df['Timestamp'] = pd.to_datetime(df['Timestamp'])
		df['Timestamp'] = (df['Timestamp'] - dt.datetime(1970,1,1)).dt.total_seconds()

		# change order of cicflowmeter output to match training dataset
		df.insert(8, 'Fwd Pkt Len Max', df.pop('Fwd Pkt Len Max'))

		return df
		
	def report_metrics(self, model_path, pcap_path, csv_path, pcap_conversion_time, prediction_time):
		report_path = 'reports/indv_pcap_performance.csv'
		# if the report doesn't already exists, write the title row first
		if os.path.isfile(report_path):
			report_headers = None
		else:
			report_headers = [
				'timestamp',
				'model_path',
				'pcap_path',
				'csv_path',
				'pcap_filesize',
				'csv_filesize',
				'pcap_conversion_time',
				'prediction_time'
			]

		row = [
			datetime.now().strftime('%Y-%m-%d %H-%M-%S'),
			model_path, 
			pcap_path, 
			csv_path, 
			os.path.getsize(pcap_path), 
			os.path.getsize(csv_path), 
			pcap_conversion_time, 
			prediction_time]

		with open(report_path, 'a') as f:
			writer = csv.writer(f)

			# if the report doesn't already exists, write the title row first
			if report_headers:
				writer.writerow(report_headers)

			writer.writerow(row)
