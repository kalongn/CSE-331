import dpkt
import socket
import numpy as np
import matplotlib.pyplot as plt

with open("trace2.pcap", "rb") as f:
    pcap_reader = dpkt.pcap.Reader(f)

    ipv4_count = 0  # 1
    non_ipv4_count = 0  # 2
    first_timestamp = None  # 3, 4
    last_timestamp = None  # 4
    total_packets = 0  # 4

    protocols = {}  # 5
    sizes = []  # 6
    sources = set()  # 7
    destinations = set()  # 8
    total_bytes = 0  # 9
    sources_byte = {}  # 9

    max_byte_source = 0  # 10
    source_mb = ""  # 10

    source_packet = {}  # 11
    max_packets_source = 0  # 11
    source_mp = ""  # 11

    for timestamp, buf in pcap_reader:
        total_packets += 1

        if first_timestamp is None:
            first_timestamp = timestamp

        last_timestamp = timestamp

        eth = dpkt.ethernet.Ethernet(buf)

        protocols[eth.type] = protocols.get(eth.type, 0) + 1

        sizes.append(len(buf))

        if eth.type == dpkt.ethernet.ETH_TYPE_IP:
            ip = eth.data
            if ip.v == 4:
                ipv4_count += 1
                sources.add(ip.src)
                sources_byte[ip.src] = sources_byte.get(ip.src, 0) + len(buf)
                source_packet[ip.src] = source_packet.get(ip.src, 0) + 1
                total_bytes += len(buf)
                destinations.add(ip.dst)

                if sources_byte[ip.src] > max_byte_source:
                    source_mb = ip.src
                    max_byte_source = sources_byte[ip.src]

                if source_packet[ip.src] > max_packets_source:
                    source_mp = ip.src
                    max_packets_source = source_packet[ip.src]
            else:
                non_ipv4_count += 1
        else:
            non_ipv4_count += 1

capture_duration = (
    last_timestamp - first_timestamp if last_timestamp and first_timestamp else 0
)
avg_packet_rate = float(total_packets) / capture_duration if capture_duration > 0 else 0

print("Count IPv4: " + str(ipv4_count))
print("Count Non-IPv4: " + str(non_ipv4_count))
print("First timestamp: %.2f" % first_timestamp)
print("Avg packet rate: %.2f packets/second" % avg_packet_rate)
print("packet protocol distribution: " + str(protocols))

plt.hist(sizes, bins=100, edgecolor="black")
plt.xlabel("Packet Size (bytes)")
plt.ylabel("Frequency")
plt.title("Packet Size Distribution")
plt.show()

print("Unique sources: " + str(len(sources)))
print("Unique destinations: " + str(len(destinations)))

sorted_bytes = sorted(sizes)
cdf = np.arange(1, len(sorted_bytes) + 1) / float(len(sorted_bytes))

plt.plot(sorted_bytes, cdf, marker="o", linestyle="--")
plt.xlabel("Bytes Sent")
plt.ylabel("Cumulative Fraction")
plt.title("CDF of Bytes Sent")
plt.grid(True)
plt.show()

print("Source sending most bytes: " + socket.inet_ntoa(source_mb))
print("Source sending most packets: " + socket.inet_ntoa(source_mp))
