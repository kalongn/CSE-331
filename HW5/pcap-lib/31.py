import dpkt

with open("trace2.pcap", "rb") as f:
    pcap_reader = dpkt.pcap.Reader(f)
    snaplen = pcap_reader.snaplen
    linktype = pcap_reader.datalink()

print("Link-layer type: " + str(linktype))

print("Snap length: " + str(snaplen) + " bytes")
