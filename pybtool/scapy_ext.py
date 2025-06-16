import fcntl
import logging
import os
import sys
import time
from scapy.packet import *
from scapy.fields import *
from scapy.layers.bluetooth import *
import socket

from pybtool.constants import HCI_DEV_DOWN
# Ideally this will shrink when scapy gets updated

SDP_PUBLIC_BROWSE_GROUP = 0x1002


class BluetoothSocket(BluetoothUserSocket):
    def __init__(self, hci_dev: int = 0):
        if os.getuid() != 0:
            logging.error("Please run as root")
            raise PermissionError("Please run as root")
        try:
            sock = socket.socket(
                socket.AF_BLUETOOTH, socket.SOCK_RAW, socket.BTPROTO_HCI
            )
            sock.bind((hci_dev,))
            fcntl.ioctl(sock.fileno(), HCI_DEV_DOWN, hci_dev)
            sock.close()

            super().__init__(hci_dev)
            logging.info(f"Opened HCI socket on device hci{hci_dev}")
        except BluetoothSocketError as e:
            logging.error(f"This should not happen {e}")
            print(e)
        except OSError as e:
            if e.errno == 19:
                logging.error(f"Device hci{hci_dev} does not exist.")
            elif e.errno == 16:
                logging.error(f"Device hci{hci_dev} is busy.")
            else:
                logging.error(f"Failed to bind device hci{hci_dev}: {e}")
                sock.close()
            print(e)

    def send_l2cap(self, handle: int, cid: int, cmd: Packet):
        self.send(HCI_Hdr() / HCI_ACL_Hdr(handle=handle) / L2CAP_Hdr(cid=cid) / cmd)

    def send_command(self, cmd: Packet) -> Packet:
        cmd = HCI_Hdr() / HCI_Command_Hdr() / cmd
        opcode = cmd[HCI_Command_Hdr].opcode
        self.send(cmd)
        while True:
            r = self.recv()
            if r.type == 0x04 and r.code == 0xE and r.opcode == opcode:
                if r.status == 0:
                    return r
                logging.error(
                    f"Command failed {cmd.lastlayer()} with status {r.status}"
                )
                return None
            elif r.type == 0x04 and r.code == 0x0F:
                if r.status == 0:
                    return r
                logging.error(f"Unknown HCI command: {cmd.lastlayer()}")
                return None

    def wait_event(self, evt: Packet, timeout: int = 5):
        pkt = self.sniff(
            timeout=timeout,
            lfilter=lambda pkt: HCI_Event_Hdr in pkt and evt in pkt,
            stop_filter=lambda pkt: HCI_Event_Hdr in pkt and evt in pkt,
        )
        if len(pkt) == 0:
            # We timed out
            return None

        # There is only the evt packet
        pkt = pkt[0]

        if "status" in pkt.fields_desc:
            if pkt.status != 0:
                logging.error(f"Command failed {evt} with status {pkt.status}")
                return None

        return pkt


class HCI_Cmd_Write_Simple_Pairing_Mode(Packet):
    """
    7.3.59 Write Simple Pairing Mode command
    """

    name = "HCI_Write_Simple_Pairing_Mode"
    fields_desc = [
        ByteEnumField(
            "simple_pairing_mode",
            0x01,
            {0x00: "disabled", 0x01: "enabled"},
        )
    ]


class HCI_Write_Secure_Connections_Host_Support(Packet):
    """
    7.3.60 Write Secure Connections Host Support command
    """

    name = "HCI_Write_Secure_Connections_Host_Support"
    fields_desc = [
        ByteEnumField(
            "secure_connections_host_support",
            0x01,
            {0x00: "disabled", 0x01: "enabled"},
        )
    ]


class HCI_Event_Pin_Code_Request(Packet):
    """
    7.1.8 Pin Code Request event
    """

    name = "HCI_Event_Pin_Code_Request"
    fields_desc = [LEMACField("bd_addr", None)]


class HCI_Event_IO_Capability_Request(Packet):
    """
    7.7.41 IO Capability Request event
    """

    # TODO: fix doxygen

    name = "HCI_IO_Capability_Request"
    fields_desc = [
        LEMACField("bd_addr", None),
    ]


class HCI_Cmd_Read_Remote_Version_Information(Packet):
    name = "HCI_Read_Remote_Version_Information"
    fields_desc = [
        LEShortField("connection_handle", None),
    ]


class HCI_Cmd_LE_Set_Public_Address(Packet):
    name = "LE Set Public Address"
    fields_desc = [LEMACField("address", None)]


class HCI_Cmd_LE_Custom_Command(Packet):
    name = "LE Custom Command"
    fields_desc = [LEShortField("opcode", 0)]


class SM_Security_Request(Packet):
    name = "Security Request"
    fields_desc = [BitField("authentication", 0, 8)]


class SDP_Hdr(Packet):
    name = "Service Discovery Protocol Header"
    fields_desc = [
        ByteEnumField(
            "pdu_id",
            0x00,
            {
                0x01: "error_resp",
                0x02: "service_search_req",
                0x03: "service_search_resp",
                0x04: "attribute_req",
                0x05: "attribute_resp",
                0x06: "service_search_attribute_req",
                0x07: "service_search_attribute_resp",
            },
        ),
        XShortField("transaction_id", 0),
        ShortField("param_length", None),
    ]

    def post_build(self, p, pay):
        if self.param_length is None and pay:
            l = len(pay)
            p = p[:3] + struct.pack(">H", l)
        return p + pay


class SDP_Error_Response(Packet):
    name = "SDP Error Response"
    fields_desc = [
        ShortEnumField(
            "error_code",
            0x0000,
            {
                0x0000: "reserved",
                0x0001: "invalid_sdp_version",
                0x0002: "invalid_service_record_handle",
                0x0003: "invalid_request_syntax",
                0x0004: "invalid_pdu_size",
                0x0005: "invalid_continuation_state",
                0x0006: "insufficient_ressources",
            },
        )
    ]


# HCI Commands
bind_layers(HCI_Command_Hdr, HCI_Cmd_Write_Simple_Pairing_Mode, ogf=0x03, ocf=0x0056)
bind_layers(
    HCI_Command_Hdr, HCI_Cmd_Read_Remote_Version_Information, ogf=0x01, ocf=0x001D
)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Public_Address, ogf=0x08, ocf=0x2004)
bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Custom_Command, ogf=0x08, ocf=0x209E)

# HCI Events
bind_layers(HCI_Event_Hdr, HCI_Event_Pin_Code_Request, code=0x16)
bind_layers(HCI_Event_Hdr, HCI_Event_IO_Capability_Request, code=0x31)

# SMP
bind_layers(SM_Hdr, SM_Security_Request, sm_command=0x0B)
