#!/usr/bin/env python3
# -------------------------------------------------------------
# File: bt-monitor.py
# Brief: PDS - Monitoring and traffic detection in BitTorrent
# Author: Tomas Hladky <xhladk15@stud.fit.vutbr.cz>
# -------------------------------------------------------------
# Date: April 9th, 2023

import os
import sys
import argparse
import logging
import socket
import struct
import datetime as dt

from scapy.packet import NoPayload

# Turn off scapy warnings at start
logging.getLogger("scapy").setLevel(logging.ERROR)

import bencode
from prettytable import PrettyTable
from scapy.layers.dns import DNS, DNSRR, dnstypes
from scapy.utils import rdpcap
from scapy.layers.inet import IP, TCP, UDP
import networkx as nx
import matplotlib.pyplot as plt
import humanize

debug_enabled = False


def main():
    parser = argparse.ArgumentParser()
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('-pcap', type=str, metavar='<pcap file>', help='pcap input file')
    input_group.add_argument('-csv', type=str, metavar='<csv file>', help='csv input file (not supported)')

    action_group = parser.add_mutually_exclusive_group(required=True)
    action_group.add_argument('-init', action='store_true', dest='init',
                              help='returns a list of detected bootstrap nodes (IP, port)')
    action_group.add_argument('-peers', action='store_true', dest='peers',
                              help='returns a list of detected neighbors (IP, port, node ID, # of conn)')
    action_group.add_argument('-download', action='store_true', dest='download',
                              help='returns file info_hash, size, chunks, contributes (IP+port)')

    parser.add_argument('-debug', action='store_true', dest='debug',
                        help='Enable debug messaging output', default=False)

    args = parser.parse_args()

    global debug_enabled
    debug_enabled = args.debug

    # Check for csv format, which is not supported
    if args.csv is not None:
        print('csv format is not supported, please specify file with pcap extension', file=sys.stderr)
        exit(1)

    # Open pcap file
    if not os.path.exists(args.pcap) or not os.path.isfile(args.pcap):
        print('Specified path to pcap file does not exists', file=sys.stderr)
        exit(1)

    if args.init:
        pcap_dht(args.pcap, True)
    elif args.peers:
        pcap_dht(args.pcap, False)
    elif args.download:
        pcap_bt(args.pcap)


def pcap_dht(pcap_filepath, init):
    DHT_REQ_PREFIX = b'd1:ad2:id20:'
    DHT_REQ_BOOTSTRAP = b'd1:ad2:bsi1e2:id20:'

    DHT_RES_PREFIX = b'd1:rd2:id20:'
    DHT_RES_IPV6_PREFIX = b'd2:ip6:'

    NODE_INFO_SIZE = 26  # in bytes: 20 (id), 4 (ip), 2 (port)

    count = 0

    # [{domain: ip} ...}]
    dns_a_recs = []

    # {cname: original_alias}
    dns_cname_recs = {}

    # {ip: port}
    dht_bootstrap_reqs = {}

    # {id: [ip, port, received_from_ip]}
    dht_table = {}

    # p2p graph structure
    g = nx.Graph()

    packets = rdpcap(pcap_filepath)
    i = 0
    for packet in packets:
        if UDP in packet:
            if DNS in packet:
                if packet[DNS].an and isinstance(packet[DNS].an, DNSRR) is not None:
                    for i in range(0, packet[DNS].ancount):
                        dns_record = packet[DNS].an[i]
                        if dnstypes[dns_record.type] == 'A':
                            dns_a_recs.append({dns_record.rrname.decode(): dns_record.rdata})
                        elif dnstypes[dns_record.type] == 'CNAME':
                            dns_cname_recs[dns_record.rdata.decode()] = dns_record.rrname.decode()
            else:
                if DHT_REQ_BOOTSTRAP in packet[UDP].load[:len(DHT_REQ_BOOTSTRAP)]:
                    dht_bootstrap_reqs[packet[IP].dst] = packet[UDP].dport
                    count += 1
                elif DHT_REQ_PREFIX in packet[UDP].load[:len(DHT_REQ_PREFIX)]:
                    count += 1
                elif DHT_RES_PREFIX in packet[UDP].load[:len(DHT_RES_PREFIX)] or \
                        DHT_RES_IPV6_PREFIX in packet[UDP].load[:len(DHT_RES_IPV6_PREFIX)]:
                    count += 1
                    response = None
                    try:
                        response = bencode.decode(packet[UDP].load)['r']
                    except bencode.exceptions.BencodeDecodeError:
                        if debug_enabled:
                            print(
                                f'DEBUG: packet {i}, (src IP: {packet[IP].src}, dst IP: {packet[IP].dst}) has invalid '
                                f'bencoding')
                            continue

                    if response is None:
                        continue

                    if 'nodes' in response:
                        nodes = bencode.decode(packet[UDP].load)['r']['nodes']

                        for i in range(0, len(nodes), NODE_INFO_SIZE):
                            id_raw = nodes[i:i + 20]
                            ip_raw = nodes[20 + i:i + 20 + 4]
                            port_raw = nodes[24 + i:i + 24 + 2]

                            id = id_raw.hex()
                            ip = socket.inet_ntoa(struct.pack('!L', int.from_bytes(ip_raw, 'big')))
                            port = int.from_bytes(port_raw, 'big')
                            received_from_ip = packet[IP].src

                            if debug_enabled:
                                if id in dht_table and ip != dht_table[id][0]:
                                    print(f'DEBUG: {id} with IP {dht_table[id][0]} already exists in DHT but acquired '
                                          f'different new IP ({ip})')
                            dht_table[id] = [ip, port, received_from_ip]

                            if not g.has_node(ip):
                                g.add_node(ip)

                            if not g.has_node(received_from_ip):
                                g.add_node(received_from_ip)

                            if not g.has_edge(ip, received_from_ip):
                                g.add_edge(ip, received_from_ip)
        i += 1

    # {domain: [ip, port, occurrences, alias]}
    bootstrap_servers = {}  # contains ip, port and number of nodes offered by the server

    # Map bootstrap ips and ports to bootstrap domain records
    for bootstrap_req_ip, bootstrap_req_port in dht_bootstrap_reqs.items():
        for rec in dns_a_recs:
            domain = list(rec.keys())[0]
            ip = list(rec.values())[0]
            if ip == bootstrap_req_ip:
                bootstrap_servers[domain] = [ip, bootstrap_req_port, 0, '']
                break

    # Rewrite CNAME domain records
    for bootstrap_key, bootstrap_value in bootstrap_servers.items():
        new_alias = bootstrap_key
        while new_alias in dns_cname_recs:
            new_alias = dns_cname_recs[new_alias]
        if new_alias != bootstrap_key:
            bootstrap_servers[bootstrap_key][3] = new_alias

    # Get bootstrap servers, that replied with node records
    for rec in dns_a_recs:
        for domain, ip in rec.items():
            for dht_key, dht_value in dht_table.items():
                if ip in dht_value[2]:
                    if domain in bootstrap_servers:
                        bootstrap_servers[domain][2] += 1
                    else:
                        bootstrap_servers[domain] = [ip, '?', 1]

    # Print bootstrap server
    if init:
        if len(bootstrap_servers) > 0:
            print('Bootstrap servers, that responded with certain number of nodes:')

            table_bstrap_servers = PrettyTable()
            table_bstrap_servers.field_names = ['Domain', 'Alias', 'IP', 'Port', 'Number of nodes received']
            for b_server_key, b_server_value in bootstrap_servers.items():
                table_bstrap_servers.add_row(
                    [b_server_key, b_server_value[3], b_server_value[0], b_server_value[1], b_server_value[2]])

            print(table_bstrap_servers)
        else:
            print('No BT-DHT Init communication found')

    else:
        # Print nodes in DHT
        if len(dht_table) > 0:
            table_dht_nodes = PrettyTable()
            table_dht_nodes.field_names = ['ID', 'IP', 'Port', 'Neighbor count']
            for dht_key, dht_value in dht_table.items():
                table_dht_nodes.add_row([dht_key, dht_value[0], dht_value[1], len(list(g.neighbors(dht_value[0])))])

            print(table_dht_nodes)

            if debug_enabled:
                nx.draw_networkx(g, node_size=0.7, font_size=0, width=0.05,
                                 alpha=0.8, node_color='#069AF390')

                ax = plt.gca()
                plt.figure(1, figsize=(1000, 1000), dpi=600)
                plt.axis("off")
                plt.tight_layout()
                plt.savefig('graph.pdf')
        else:
            print('No BT-DHT communication found')


def pcap_bt(pcap_filepath):
    packets = rdpcap(pcap_filepath)

    BITTORRENT_MSG_PREFIX = b'\x13\x42\x69\x74\x54\x6f\x72\x72\x65\x6e\x74\x20\x70\x72\x6f\x74\x6f\x63\x6f\x6c'  #
    # "0x13Bittorent protocol"

    EXTENSION_RESERVE_BYTES = 8
    SHA1_SIZE = 20

    PIECE_MSG_LEN_SIZE = 4
    PIECE_MSG_INDEX_SIZE = 4

    # Store handshake that has been sent to peers to know from which one expect answer
    # {{ip_src}_{ip_dst}: Int}
    handshake_send_msgs = {}

    # {ip: {port, handshake, info_hash}}
    handshake_rcv_msgs = {}

    # {info_hash: piece_count}
    files = {}

    # {ip: [{time, piece_index, block_size}]}
    transfers = {}

    # Detect 3 types of BT messages: Handshake, Bitfield, Piece
    for packet in packets:
        process_handshake = False
        process_piece = False
        process_udp_bitfield = False

        packet_sport = 0
        load = None
        udp_bitfield_start = 0

        if UDP in packet:
            if DNS in packet or len(packet[UDP]) == 0 or isinstance(packet[UDP].payload, NoPayload):
                continue
            else:
                load = packet[UDP].load

                # 16393 bytes data length + 7 message type "Piece"
                if b'\x00\x00\x40\x09\x07' in load:
                    process_piece = True
                elif BITTORRENT_MSG_PREFIX in load:
                    packet_sport = packet[UDP].sport
                    process_handshake = True

                    # Detect potential "bitfield" message right after "handshake" message
                    # Detection assumes that peer fully owns first pieces marked with first 4 bytes
                    if b'\x05\xff\xff\xff\xff' in load:
                        process_udp_bitfield = True
                        udp_bitfield_start = load.index(b'\x05\xff\xff\xff\xff') + 1

        elif TCP in packet:
            if len(packet[TCP]) == 0 or isinstance(packet[TCP].payload, NoPayload):
                continue
            else:
                load = packet[TCP].load

                # Detect "Bitfield" message
                # 1st condition: 05 is code for message type Bitfield
                # 2nd condition: Message length (including message code) is stored in first 4 bytes,
                # thus this value can be compared to real byte length
                if f'{packet[IP].src}_{packet[IP].dst}' in handshake_send_msgs and \
                        packet[IP].src in handshake_rcv_msgs and \
                        handshake_send_msgs[f'{packet[IP].src}_{packet[IP].dst}'] == 1 and \
                        handshake_rcv_msgs[packet[IP].src]['handshake'][-1] == 0x05 and \
                        int.from_bytes(handshake_rcv_msgs[packet[IP].src]['handshake'][-4:-1], 'big') - 1 == len(load):
                    handshake_send_msgs[
                        f'{packet[IP].src}_{packet[IP].dst}'] = 2  # Mark handshake with this peer as done

                    piece_count = 0
                    for piece in load:
                        piece_count += count_bit_ones(piece)

                    if handshake_rcv_msgs[packet[IP].src]['info_hash'] not in files or \
                            files[handshake_rcv_msgs[packet[IP].src]['info_hash']] < piece_count:
                        files[handshake_rcv_msgs[packet[IP].src]['info_hash']] = piece_count

                # Detect "Handshake" message
                if load[:len(BITTORRENT_MSG_PREFIX)] == BITTORRENT_MSG_PREFIX:
                    packet_sport = packet[TCP].sport
                    process_handshake = True

                # Detect "Piece" message
                if b'\x00\x00\x40\x09\x07' in load:
                    process_piece = True

        # Process "Piece" message for both TCP and UDP
        if process_piece:
            piece_msg_start = load.index(b'\x00\x00\x40\x09\x07')

            # To determine whether packet is Bittorrent, check also
            # 1st byte of "Piece index" and 1st byte of "Begin offset of piece"
            # This will work until there are too many pieces
            if piece_msg_start + len(b'\x00\x00\x40\x09\x07') + PIECE_MSG_INDEX_SIZE < len(load) and \
                    load[piece_msg_start + len(b'\x00\x00\x40\x09\x07')] == 0x00 and \
                    load[piece_msg_start + len(b'\x00\x00\x40\x09\x07') + PIECE_MSG_INDEX_SIZE] == 0x00:

                piece_index = load[piece_msg_start + len(b'\x00\x00\x40\x09\x07'):piece_msg_start + len(
                    b'\x00\x00\x40\x09\x07') + PIECE_MSG_INDEX_SIZE].hex()
                block_size = int.from_bytes(b'\x00\x00\x40\x09', 'big')

                if packet[IP].src not in transfers:
                    transfers[packet[IP].src] = []

                transfers[packet[IP].src].append({'time': packet.time, 'piece_index': piece_index,
                                                  'block_size': block_size})

        # Process "Handshake" message for both TCP and UDP
        elif process_handshake:
            handshake_msg_start = load.index(BITTORRENT_MSG_PREFIX)
            if f'{packet[IP].src}_{packet[IP].dst}' in handshake_send_msgs:
                info_hash_start = handshake_msg_start + len(BITTORRENT_MSG_PREFIX) + EXTENSION_RESERVE_BYTES
                info_hash_end = handshake_msg_start + len(BITTORRENT_MSG_PREFIX) + EXTENSION_RESERVE_BYTES + SHA1_SIZE
                handshake_rcv_msgs[packet[IP].src] = {'port': packet_sport, 'handshake': load,
                                                      'info_hash': load[info_hash_start:info_hash_end].hex()}
            elif not packet[IP].dst in handshake_send_msgs:
                handshake_send_msgs[f'{packet[IP].dst}_{packet[IP].src}'] = 1

        # Separate process for UDP because it is stored with the handshake message (in the end)
        if process_udp_bitfield:
            if packet[IP].src in handshake_rcv_msgs and \
                    handshake_send_msgs[f'{packet[IP].src}_{packet[IP].dst}'] == 1:
                handshake_send_msgs[f'{packet[IP].src}_{packet[IP].dst}'] = 2  # Mark handshake with this peer as done

                # In UDP, bitfield may not be stored in one packet
                # This approximate piece by acquiring it from message length before message type
                piece_count = int.from_bytes(load[udp_bitfield_start-1-4:udp_bitfield_start-1], 'big') * 8 - 8

                if handshake_rcv_msgs[packet[IP].src]['info_hash'] not in files or \
                        files[handshake_rcv_msgs[packet[IP].src]['info_hash']] < piece_count:
                    files[handshake_rcv_msgs[packet[IP].src]['info_hash']] = piece_count

    first_file_print = True
    i = 0
    for file_info_hash, file_piece_count in files.items():
        # {index: count}
        piece_indexes = {}

        # {index: {ip: count}}
        piece_ips = {}

        # For specific filehash
        # {ip: {port, piece_count, time}}
        peer_download_info = {}

        block_size = 0

        if not first_file_print:
            print()  # Print empty line as separator

        print(f'Torrent {i + 1}/{len(files)}:')

        for transfer_key, transfer_value in transfers.items():
            if transfer_key in handshake_rcv_msgs and \
                    handshake_rcv_msgs[transfer_key]['info_hash'] == file_info_hash and \
                    len(transfer_value) > 0:

                for single_piece in transfer_value:
                    if single_piece['piece_index'] not in piece_indexes:
                        piece_indexes[single_piece['piece_index']] = 1
                    else:
                        piece_indexes[single_piece['piece_index']] += 1

                    if single_piece['piece_index'] not in piece_ips:
                        piece_ips[single_piece['piece_index']] = {}

                    if transfer_key not in piece_ips[single_piece['piece_index']]:
                        piece_ips[single_piece['piece_index']][transfer_key] = 1
                    else:
                        piece_ips[single_piece['piece_index']][transfer_key] += 1

                    if single_piece['block_size'] > block_size:
                        block_size = single_piece['block_size']

                    if transfer_key not in peer_download_info:
                        peer_download_info[transfer_key] = {'port': handshake_rcv_msgs[transfer_key]['port'],
                                                            'time': transfer_value[-1]['time'] - transfer_value[-0][
                                                                'time'],
                                                            'piece_count': 1}
                    else:
                        peer_download_info[transfer_key]['piece_count'] += 1

        block_count_est = 0
        if len(piece_indexes) > 0:
            if len(piece_indexes.values()) <= 12:
                # Special case, when there is not enough data
                piece_indexes_key_max = list(piece_indexes.keys())[
                    list(piece_indexes.values()).index(max(piece_indexes.values()))]
                block_count_est = max(piece_ips[piece_indexes_key_max].values())
            else:
                block_count_est = round(sum(piece_indexes.values()) / len(piece_indexes.values()))

        if debug_enabled:
            print(f'DEBUG: Estimated block count per piece: {block_count_est}')

        if debug_enabled:
            print(f'DEBUG: Estimated number of total pieces {file_piece_count}')

        total_size = file_piece_count * block_size * block_count_est

        if file_piece_count == 0 or block_size == 0 or block_count_est == 0:
            print('No torrent "piece" messages detected')
            i += 1
            if first_file_print:
                first_file_print = False
            continue

        peers_total_download = 0
        peers_num_of_blocks = 0
        for _, peer_value in peer_download_info.items():
            peers_total_download += peer_value["piece_count"] * block_size
            peers_num_of_blocks += peer_value["piece_count"]

        if debug_enabled:
            print(f'DEBUG: Estimated number of downloaded pieces {round(peers_num_of_blocks / block_count_est)}')

        info_table = PrettyTable()
        info_table.field_names = ['Info hash', 'Total size est.', 'Total % downloaded est.']
        info_table.add_row([f'{file_info_hash}',
                            f'{humanize.naturalsize(total_size, binary=False, format="%.2f")} ({humanize.naturalsize(total_size, binary=True, format="%.2f")})',
                            f'{"{:.1f}".format(peers_total_download / total_size * 100)}%'])
        print(info_table)

        table_download = PrettyTable()
        table_download.field_names = ['Peer IP + Port', 'Amount downloaded', '% downloaded',
                                      'Estimated downloading time']

        for peer_key, peer_value in peer_download_info.items():
            table_download.add_row([f'{peer_key}:{peer_value["port"]}',
                                    f'{humanize.naturalsize(peer_value["piece_count"] * block_size, binary=False, format="%.2f")} ({humanize.naturalsize(peer_value["piece_count"] * block_size, binary=True, format="%.2f")})',
                                    f'{"{:.1f}".format(peer_value["piece_count"] * block_size / total_size * 100)}%',
                                    f'{humanize.precisedelta(dt.timedelta(seconds=float(peer_value["time"])))}'])

        print(table_download)

        if first_file_print:
            first_file_print = False

        i += 1

    if len(files) == 0:
        print("No torrent communication detected")


def count_bit_ones(number):
    return bin(number).replace('0b', '').count('1')


if __name__ == '__main__':
    main()
