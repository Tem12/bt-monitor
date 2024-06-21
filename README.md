# Monitoring and traffic detection in BitTorrent

Author: Tomáš Hladký <xhladk15@stud.fit.vutbr.cz>

**bt-monitor** is a tool that enables the detection and retrospective monitoring
of BitTorrent traffic communication. The tool can detect torrent protocols from pcap files and create a graph of the peer-to-peer network with analysis of torrent downloads. The outcome from analysis contains information that can be used in further processing, such as the detection of downloads of files protected by copyright.

bt-monitor is implemented in Python 3 and requires to install additional modules specified in `requirements.txt` using `pip3`.

```
usage: bt-monitor.py [-h] (-pcap <pcap file> | -csv <csv file>) (-init | -peers | -download) [-debug]

options:
  -h, --help         show this help message and exit
  -pcap <pcap file>  pcap input file
  -csv <csv file>    csv input file (not supported)
  -init              returns a list of detected bootstrap nodes (IP, port)
  -peers             returns a list of detected neighbors (IP, port, node ID, # of conn)
  -download          returns file info_hash, size, chunks, contributes (IP+port)
  -debug             Enable debug messaging output
