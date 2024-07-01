import scapy.all as scapy
import pandas as pd
from datetime import datetime

def parse_pcap(file_path):
    packets = scapy.rdpcap(file_path)
    parsed_data = []
    
    for packet in packets:
        packet_data = {
            'timestamp': datetime.fromtimestamp(packet.time),
            'src_ip': packet[scapy.IP].src if packet.haslayer(scapy.IP) else None,
            'dst_ip': packet[scapy.IP].dst if packet.haslayer(scapy.IP) else None,
            'protocol': packet[scapy.IP].proto if packet.haslayer(scapy.IP) else None,
            'payload': bytes(packet[scapy.IP].payload) if packet.haslayer(scapy.IP) else None
        }
        parsed_data.append(packet_data)
    
    return pd.DataFrame(parsed_data)

def identify_suspicious_activity(df):
    # Placeholder for actual analysis logic
    suspicious_ips = ['192.168.1.1']  # Example suspicious IP
    df['suspicious'] = df['src_ip'].apply(lambda x: 'Yes' if x in suspicious_ips else 'No')
    return df

def generate_report(df, output_path):
    df.to_csv(output_path, index=False)
    print(f"Report generated: {output_path}")

if __name__ == "__main__":
    pcap_file = 'sample.pcap'  # Replace with your actual pcap file path
    output_file = 'report.csv'
    
    print("Parsing PCAP file...")
    parsed_df = parse_pcap(pcap_file)
    
    print("Identifying suspicious activity...")
    analyzed_df = identify_suspicious_activity(parsed_df)
    
    print("Generating report...")
    generate_report(analyzed_df, output_file)
