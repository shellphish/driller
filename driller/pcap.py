import dpkt
import logging

l = logging.getLogger("fuzzer.pcap")

def _connection_streams(filename):
    filestream = open(filename)
    pcap = dpkt.pcap.Reader(filestream)
    out = []
    lookup = {}
    for _, packet in pcap:
        ip = dpkt.ethernet.Ethernet(packet).ip
        tcp = ip.data
        if tcp.data == '': 
            continue

        is_recv = ip.dst == b'\x7f\x00\x00\x01'
        key = (tcp.sport, tcp.dport) if is_recv else (tcp.dport, tcp.sport)
        if key not in lookup:
            lookup[key] = len(out)
            out.append([])
        index = lookup[key]

        if len(out[index]) > 0 and is_recv and out[index][-1]['direction'] == 'recv':
            out[index][-1]['data'] += tcp.data
        else:
            out[index].append({
                'direction': 'recv' if is_recv else 'send',
                'data': tcp.data
            })
    filestream.close()
    return out 

def process(pcap_path):
    l.debug("received path '%s' to process as a pcap", pcap_path)

    streams = _connection_streams(pcap_path)

    # concat all the send streams together
    seeds = [ ]
    for stream in streams:
        inp = [ ]
        for pkt in stream:
            if pkt['direction'] == 'send':
                inp.append(pkt['data'])
        inp = ''.join(inp)
        seeds.append(inp)

    return seeds
