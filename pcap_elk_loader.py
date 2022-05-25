import datetime
import pyshark
from elasticsearch import Elasticsearch, helpers, exceptions

# Give the .pcap file path
CAPTURE_FILE = "dns_capture.pcap"

template = {

    "settings": {
        "index.mapping.total_fields.limit": 1000000,
        "index.mapping.ignore_malformed": "true",
        "index.mapping.coerce": "true"
    },
    "mappings": {
        "properties": {
            "timestamp": {"type": "date"},
            "dns_a": {"type": "text"},
            "dns_aaaa": {"type": "text"},
            "dns_count_labels": {"type": "text"},
            "dns_id": {"type": "text"},
            "dns_qry_class": {"type": "text"},
            "dns_qry_name": {"type": "text"},
            "dns_qry_name_len": {"type": "text"},
            "dns_qry_type": {"type": "text"},
            "dns_resp_class": {"type": "text"},
            "dns_resp_len": {"type": "text"},
            "dns_resp_name": {"type": "text"},
            "dns_resp_ttl": {"type": "text"},
            "dns_resp_type": {"type": "text"},
            "dns_time": {"type": "text"},
            "eth_dst": {"type": "text"},
            "eth_src": {"type": "text"},
            "ip_dst": {"type": "text"},
            "ip_proto": {"type": "text"},
            "ip_src": {"type": "text"},
            "udp_dstport": {"type": "text"},
            "udp_srcport": {"type": "text"}
        }
    }
}

es = Elasticsearch("http://localhost:9200")

# Creating the Index Template if it's not exists:

INDEX_TEMPLATE_NAME = 'packet_templates'
INDEX_PATTERNS = "packets-*"

try:
    es.indices.get_index_template(name=INDEX_TEMPLATE_NAME)

except exceptions.NotFoundError:
    es.indices.put_index_template(
        name=INDEX_TEMPLATE_NAME, template=template, index_patterns=INDEX_PATTERNS)
    print("Index template not found. So new index templated Created.")


capture = pyshark.FileCapture(input_file=CAPTURE_FILE)


def get_list(obj):
    return [
        item.showname_value for item in obj.all_fields] if obj else []


for packet in capture:

    if 'DNS' not in packet:
        continue

    # Timestamp in Milliseconds
    TIMESTAMP = int(float(packet.sniff_timestamp)*1000)
    TIMESTAMP = packet.sniff_time

    # Index:
    INDEX = f'packets-{datetime.date.today()}'

    # MAC ADDRESS
    SOURCE_ETH_ADDR = get_list(packet.eth.get('src', ''))
    DESTINATION_ETH_ADDR = get_list(packet.eth.get('dst', ''))

    # IP Address
    SOURCE_IP = get_list(packet.ip.get('src', ''))
    DESTINATION_IP = get_list(packet.ip.get('dst', ''))

    # Protocol
    PROTOCOL = get_list(packet.ip.get('proto', ''))

    # Port
    SOURCE_PORT_UDP = ''
    DESTINATION_PORT_UDP = ''

    # DNS Query
    DNS_ID = ''
    DNS_QRY_NAME = ''
    DNS_QRY_NAME_LEN = ''
    DNS_COUNT_LABELS = ''
    DNS_QRY_TYPE = ''
    DNS_QRY_CLASS = ''

    DNS_TIME = ''

    # DNS Response
    DNS_RESP_NAME = ''
    DNS_RESP_LEN = ''
    DNS_RESP_TYPE = ''
    DNS_RESP_CLASS = ''
    DNS_RESP_TTL = ''
    DNS_A = ''
    DNS_AAAA = ''

    if 'UDP' in packet:
        SOURCE_PORT_UDP = get_list(packet.udp.get('srcport', ''))
        DESTINATION_PORT_UDP = get_list(packet.udp.get('dstport', ''))

    if 'TCP' in packet:
        SOURCE_PORT_UDP = get_list(packet.tcp.get('srcport', ''))
        DESTINATION_PORT_UDP = get_list(packet.tcp.get('dstport', ''))

    if 'DNS' in packet:

        DNS_ID = get_list(packet.dns.get('id', ''))
        DNS_QRY_NAME = get_list(packet.dns.get('qry_name', ''))
        DNS_QRY_NAME_LEN = get_list(packet.dns.get('qry_name_len', ''))
        DNS_COUNT_LABELS = get_list(packet.dns.get('count_labels', ''))
        DNS_QRY_TYPE = get_list(packet.dns.get('qry_type', ''))
        DNS_QRY_CLASS = get_list(packet.dns.get('qry_class', ''))

        DNS_TIME = get_list(packet.dns.get('time', ''))

        DNS_RESP_NAME = get_list(packet.dns.get('resp_name', ''))
        DNS_RESP_LEN = get_list(packet.dns.get('resp_len', ''))
        DNS_RESP_TYPE = get_list(packet.dns.get('resp_type', ''))
        DNS_RESP_CLASS = get_list(packet.dns.get('resp_class', ''))
        DNS_RESP_TTL = get_list(packet.dns.get('resp_ttl', ''))
        DNS_A = get_list(packet.dns.get('a', ''))
        DNS_AAAA = get_list(packet.dns.get('aaaa', ''))

    value = {

        "_index": INDEX,
        "timestamp": TIMESTAMP,
        "eth_src": SOURCE_ETH_ADDR,
        "eth_dst": DESTINATION_ETH_ADDR,
        "ip_src": SOURCE_IP,
        "ip_dst": DESTINATION_IP,
        "udp_srcport": SOURCE_PORT_UDP,
        "udp_dstport": DESTINATION_PORT_UDP,
        "ip_proto": PROTOCOL,
        "dns_id": DNS_ID,
        "dns_qry_name": DNS_QRY_NAME,
        "dns_qry_name_len": DNS_QRY_NAME_LEN,
        "dns_count_labels": DNS_COUNT_LABELS,
        "dns_qry_type": DNS_QRY_TYPE,
        "dns_qry_class": DNS_QRY_CLASS,
        "dns_time": DNS_TIME,
        "dns_resp_name": DNS_RESP_NAME,
        "dns_resp_len": DNS_RESP_LEN,
        "dns_resp_type": DNS_RESP_TYPE,
        "dns_resp_class": DNS_RESP_CLASS,
        "dns_resp_ttl": DNS_RESP_TTL,
        "dns_a": DNS_A,
        "dns_aaaa": DNS_AAAA

    }

    final_value = {k: v for k, v in value.items() if v}
    helpers.bulk(es, [final_value])
    # print(final_value['dns_qry_name'])
    # print(final_value)
