import pyshark
import os
import configparser
import sys
import pandas as pd
import IDS as ids


def main():
    print('welcome to main function')

    if len(sys.argv) < 2:
        print("Error: Please provide the configuration section name (e.g., 'params').")
        return

    params = sys.argv[1]
    config = configparser.ConfigParser()
    config.read("Conf.conf")

    if params not in config:
        print(f"Error: Section '{params}' not found in Conf.conf")
        return

    params_config = config[params]
    exe = ids.IDS(params_config)

    is_sniffing = params_config.get('sniffing') == '1'
    source = params_config.get('NIC') if is_sniffing else params_config.get('PCAP_FILE')
    timeout = 10 if is_sniffing else None

    if source:
        print(f"Starting analysis on source: {source}")
        try:
            exe.start_analysis(source, is_sniffing, timeout)

        except Exception as e:
            print(f"[CRITICAL ERROR] Failed to run analysis: {e}")

    else:
        print("Configuration error: Source (NIC or PCAP_FILE) is missing.")


if __name__ == "__main__":
    main()
