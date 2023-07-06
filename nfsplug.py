import argparse
import nfstream

def process_pcap(pcap_file):
    my_streamer = nfstream.NFStreamer(
        source=pcap_file,
        decode_tunnels=True,
        bpf_filter=None,
        promiscuous_mode=True,
        snapshot_length=1536,
        idle_timeout=120,
        active_timeout=1800,
        accounting_mode=0,
        udps=None,
        n_dissections=20,
        statistical_analysis=False,
        splt_analysis=0,
        n_meters=0,
        max_nflows=0,
        performance_report=0,
        system_visibility_mode=0,
        system_visibility_poll_ms=100
    )

    for flow in my_streamer:
        print(flow)  # or perform other operations with the flow data

    my_dataframe = my_streamer.to_pandas(columns_to_anonymize=[])
    print(my_dataframe.head())

    total_flows_count = my_streamer.to_csv(
        path=None, columns_to_anonymize=[], flows_per_file=0, rotate_files=0
    )
    print("Total flows count:", total_flows_count)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='nfstream pcap analysis')
    parser.add_argument('pcap_file', help='Path to the pcap file')
    args = parser.parse_args()

    pcap_file = args.pcap_file

    process_pcap(pcap_file)
