"""
Модуль извлечения признаков из сетевых пакетов.
Каждый пакет превращается в набор полей, пригодных для анализа.
"""

from datetime import datetime

from scapy.all import ICMP, IP, TCP, UDP


def extract_features(packet):
    """
    Извлекает ключевые поля из пакета.

    Returns:
        dict: словарь с признаками пакета, или None если пакет не IP.
    """
    if IP not in packet:
        return None

    ip = packet[IP]
    features = {
        "timestamp": datetime.now(),
        "src_ip": ip.src,
        "dst_ip": ip.dst,
        "packet_size": len(packet),
        "protocol": None,
        "src_port": None,
        "dst_port": None,
        "tcp_flags": None,
        "icmp_type": None,
    }

    if TCP in packet:
        features["protocol"] = "TCP"
        features["src_port"] = packet[TCP].sport
        features["dst_port"] = packet[TCP].dport
        features["tcp_flags"] = str(packet[TCP].flags)

    elif UDP in packet:
        features["protocol"] = "UDP"
        features["src_port"] = packet[UDP].sport
        features["dst_port"] = packet[UDP].dport

    elif ICMP in packet:
        features["protocol"] = "ICMP"
        features["icmp_type"] = packet[ICMP].type

    else:
        features["protocol"] = "OTHER"

    return features
