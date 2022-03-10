import os

from CaptureTraffic import CaptureTraffic
from PcapConverter import PcapConverter

base_path = os.path.dirname(os.path.realpath(__file__))
models_directory_path = base_path + '/models/'
model_name = 'random_forrest_model-20211010-175531.sav'
pcap_dir = base_path + '/data/pcaps/'
csv_dir = base_path + '/data/ids_input/'


def main():
    pcap_converter = PcapConverter(pcap_dir, csv_dir)

    pcap_capture = CaptureTraffic("ens33", pcap_dir, 1000)
    pcap_capture.start()

    while True:
        u_input = input('IDS: ')

        if u_input == 'kill':
            pcap_capture.kill()


if __name__ == '__main__':
    main()