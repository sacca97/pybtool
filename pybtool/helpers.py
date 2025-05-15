from scapy.packet import *
from scapy.fields import *
from scapy.layers.bluetooth import *


def get_adv_info(pkt):
    dev = {}
    if HCI_Event_Inquiry_Result in pkt:
        return (pkt.addr[0], "BREDR", None)
    elif HCI_LE_Meta_Advertising_Report in pkt:
        pkt = pkt[HCI_LE_Meta_Advertising_Report]
        return (pkt.addr), "BLE", get_name_from_adv(pkt)

    return None, None, None


def get_name_from_adv(pkt: HCI_LE_Meta_Advertising_Report) -> str:
    if pkt.len > 0:
        # Check if the packet has a complete local name
        name = [itm for itm in pkt.data if EIR_CompleteLocalName in itm]
        if len(name) > 0:
            return name[0].local_name.decode()
    return None


def parse_adv_results(pkts) -> dict:
    output = {}
    for pkt in pkts:
        addr, btype, _ = get_adv_info(pkt)
        output[addr] = btype
    return output


def extract_features(pkt: HCI_Event_Read_Remote_Extended_Features_Complete, page: int):
    if page == 1:
        ext_feat = {
            "secure_simple_pairing_host_support": (pkt.extended_features >> 0) & 1,
            "le_supported_host": (pkt.extended_features >> 1) & 1,
            "secure_connections_host_support": (pkt.extended_features >> 3) & 1,
        }
        return [key for key, value in ext_feat.items() if value == 1]

    if page == 2:
        sc_ctrl = (pkt.extended_features >> 8) & 1
        return ["secure_connections_controller_support"] if sc_ctrl == 1 else []
