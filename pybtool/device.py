from abc import ABC
from scapy.packet import *
from scapy.fields import *
from scapy.layers.bluetooth import *
from pybtool.constants import *
from pybtool.scapy_ext import *
from pybtool.helpers import (
    extract_features,
    get_name_from_adv,
    get_adv_info,
    parse_adv_results,
)


class RemoteDevice:
    def __init__(self, addr: str, handle: int = None, connected: bool = False):
        self.handle: int = handle
        self.addr: str = addr
        self.connected = connected
        self.bonded = False
        self.ltk = None
        self.encrypted = False
        self.io_capabilities = None
        self.auth_requirements = None
        self.features = []
        self.version = None
        self.manufacturer = None

    def __eq__(self, other):
        if not isinstance(other, RemoteDevice):
            return False
        return self.addr == other.addr

    def __hash__(self):
        return hash(self.addr)

    def __str__(self):
        return f"RemoteDevice(addr={self.addr}, handle={self.handle})"


class Device(ABC):
    peer: RemoteDevice = None

    def __init__(
        self, bt_addr: str = None, bt_mode: int = BT_MODE_DUAL, hci_dev: int = 0
    ):
        self.bt_addr = bt_addr
        self.bt_mode = bt_mode
        self.hci_dev_idx = hci_dev
        self.hci_dev = None
        if bt_mode != BT_MODE_BREDR:
            # Init SMP
            pass

    def __str__(self):
        return f"Device(bt_addr={self.bt_addr}, bt_mode={self.bt_mode})"

    def power_on(self):
        """
        Power on the device.
        """
        self.hci_dev = BluetoothSocket(self.hci_dev_idx)
        self.send_command(HCI_Cmd_Reset())
        self.send_command(HCI_Cmd_Set_Event_Mask())

        if self.bt_mode in (BT_MODE_BREDR, BT_MODE_DUAL):
            self.send_command(HCI_Cmd_Write_Simple_Pairing_Mode())

    def power_off(self):
        """
        Power off the device.
        """
        if self.hci_dev:
            self.hci_dev.close()
            self.hci_dev = None
            self.hci_dev_idx = -1

    def send_command(self, cmd: Packet) -> Packet:
        if self.hci_dev:
            return self.hci_dev.send_command(cmd)

        logging.error("HCI device is not initialized.")

    def wait_for_event(self, event: int, timeout: int = 5) -> Packet:
        """
        Wait for an event from the device.
        """
        if self.hci_dev:
            return self.hci_dev.wait_event(event, timeout)

        logging.error("HCI device is not initialized.")

    def scan(self, target: str = None, timeout: int = 5, print_info: bool = False):
        """
        Scan for devices. If target is specified, returns the target info if found, None otherwise.
        """

        if self.bt_mode in (BT_MODE_BLE, BT_MODE_DUAL):
            self.send_command(HCI_Cmd_LE_Set_Scan_Parameters(type=0))
            self.send_command(HCI_Cmd_LE_Set_Scan_Enable(enable=1, filter_dups=1))

        if self.bt_mode in (BT_MODE_BREDR, BT_MODE_DUAL):
            self.send_command(HCI_Cmd_Inquiry(inquiry_length=timeout))

        start_time = time.time()
        while time.time() - start_time < timeout:
            pkt = self.hci_dev.recv()
            addr, bt_type, name = get_adv_info(pkt)
            if addr is None:
                continue

            if print_info:
                print(f"Found device: {addr}, type: {bt_type}, name: {name}")

            if target == addr:
                if self.bt_mode in (BT_MODE_BLE, BT_MODE_DUAL):
                    self.send_command(HCI_Cmd_LE_Set_Scan_Enable(enable=0))
                if self.bt_mode in (BT_MODE_BREDR, BT_MODE_DUAL):
                    self.send_command(HCI_Cmd_Inquiry_Cancel())
                return bt_type

            elif HCI_Event_Inquiry_Complete in pkt:
                break

        # Stop BLE scanning, BREDR scanning is stopped automatically
        if self.bt_mode in (BT_MODE_BLE, BT_MODE_DUAL):
            self.send_command(HCI_Cmd_LE_Set_Scan_Enable(enable=0))

        return None

    def connect(self, addr: str, addr_type: int = 1, bt_type: int = BT_MODE_BREDR):
        """
        Connect to a remote device.
        """
        res = None
        if bt_type == BT_MODE_BLE:
            self.send_command(
                HCI_Cmd_LE_Create_Connection(paddr=addr, patype=addr_type)
            )
            res = self.wait_for_event(HCI_LE_Meta_Connection_Complete)
        elif bt_type == BT_MODE_BREDR:
            self.send_command(HCI_Cmd_Create_Connection(bd_addr=addr))
            res = self.wait_for_event(HCI_Event_Connection_Complete)

        if res is not None:
            logging.info("Device connected")
            addr = res.bd_addr if HCI_Event_Connection_Complete in res else res.paddr
            self.peer = RemoteDevice(addr=addr, handle=res.handle, connected=True)
            return True

        logging.warning(f"Connection timed out {addr}")
        return False

    def disconnect(self):
        if self.peer is None or not self.peer.connected:
            logging.debug("Device is not connected")
            return True

        self.send_command(HCI_Cmd_Disconnect(handle=self.peer.handle))
        pkt = self.wait_for_event(HCI_Event_Disconnection_Complete)
        if pkt is None:
            logging.debug("Disconnection failed")
            return False

        self.peer.connected = False
        return True

    def get_remote_features(self):
        if self.peer is None or not self.peer.connected:
            logging.debug("Device is not connected")
            return []

        self.send_command(
            HCI_Cmd_Read_Remote_Supported_Features(connection_handle=self.peer.handle),
        )
        pkt = self.wait_for_event(HCI_Event_Read_Remote_Supported_Features_Complete)

        if pkt is None:
            return []

        features = [str(f) for f in pkt.lmp_features]

        if "extended_features" not in features:
            return features

        self.send_command(
            HCI_Cmd_Read_Remote_Extended_Features(
                connection_handle=self.peer.handle, page_number=0x01
            ),
        )
        pkt = self.wait_for_event(HCI_Event_Read_Remote_Extended_Features_Complete)
        features += extract_features(pkt, page=1)

        # TODO: check if we need to read page 2

        return features

    def get_remote_version(self):
        if self.peer is None or not self.peer.connected:
            logging.debug("Device is not connected")
            return None, None

        self.send_command(
            HCI_Cmd_Read_Remote_Version_Information(connection_handle=self.peer.handle),
        )
        pkt = self.wait_for_event(HCI_Event_Read_Remote_Version_Information_Complete)
        if pkt is None:
            return None, None

        logging.debug(f"Bluetooth version: {bt_version_table[pkt.version]}")
        # # print(f"Subversion: {pkt.subversion}")
        logging.debug(
            f"Chip manufacturer: {bt_manufacturer_table[pkt.manufacturer_name]}"
        )
        return (
            bt_version_table[pkt.version],
            bt_manufacturer_table[pkt.manufacturer_name],
        )

    # Only for BREDR
    def pair(self, timeout: int = 5):
        def pairing_handler(pkt: Packet):
            if HCI_Event_Link_Key_Request in pkt:
                self.send_command(
                    HCI_Cmd_Link_Key_Request_Negative_Reply(bd_addr=pkt.bd_addr),
                )
            elif HCI_Event_IO_Capability_Request in pkt:
                self.send_command(
                    HCI_Cmd_IO_Capability_Request_Reply(
                        bd_addr=pkt.bd_addr,
                        io_capability=0x03,  # No input, no output
                        oob_data_present=0x00,  # No OOB
                        authentication_requirement=0x04,  # Dedicated pairing
                    ),
                )
            elif HCI_Event_IO_Capability_Response in pkt:
                self.peer.io_capabilities = pkt.io_capability
                self.peer.auth_requirements = pkt.authentication_requirements

                logging.debug(
                    f"IO Capability: {io_capabilities.get(pkt.io_capability, 'NoInputNoOutput')} Authentication: {auth_requirements.get(pkt.authentication_requirements)}"
                )

            if HCI_Event_Hdr in pkt:
                return True
            return False

        if self.peer is None or not self.peer.connected:
            logging.info("Device is not connected")
            return False, None

        self.send_command(
            HCI_Cmd_Authentication_Requested(handle=self.peer.handle),
        )
        # TODO: pairing should be completed in 2-3 seconds max
        self.hci_dev.sniff(
            timeout=timeout,
            lfilter=lambda pkt: pairing_handler(pkt),
            stop_filter=lambda pkt: HCI_Event_IO_Capability_Response
            in pkt,  # TODO: change this
            store=False,
        )
        if self.peer.io_capabilities is None:
            logging.error("Pairing failed")
            return False, None

        return True, {
            "io_capabilities": io_capabilities.get(
                self.peer.io_capabilities, "NoInputNoOutput"
            ),
            "auth_req": auth_requirements.get(self.peer.auth_requirements),
        }
