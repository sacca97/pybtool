import logging
from typing import Optional, Tuple
from scapy.layers.bluetooth import *
from constants import *
from pybtool.crypto import *
from helpers import *
from pybtool.scapy_ext import BluetoothSocket, SM_Security_Request


class SecurityManager:

    ea: bytes
    eb: bytes
    ltk: bytes
    preq: bytes
    pres: bytes
    tk: bytes


    def __init__(self, hci_dev: BluetoothSocket, role: int):
        self.mitm = 0
        self.sc = 1
        self.bond = 1
        self.keypress = 0
        self.ct2 = 1
        self.ltk_size = 16
        self.ecc_key: Optional[EccKey] = EccKey.generate()
        self.peer_random_value: Optional[bytes] = None
        self.peer_public_key_x: bytes = bytes(32)
        self.peer_public_key_y = bytes(32)
        self.role = role
        self.r: bytes
        self.dhkey = None
        self.ltk = None
        self.confirm_value = 0

        self.ia = bytes(6)  # Initiator address
        self.ra = bytes(6)  # Responder address
        self.iat = 0  # Initiator address type
        self.rat = 0  # Responder address type

        self.hci_dev = hci_dev

    @property
    def authreq(self):
        return self.bond << 0 | self.mitm << 2 | self.sc << 3 | self.keypress << 4

    @property
    def pkx(self) -> Tuple[bytes, bytes]:
        return (self.ecc_key.x[::-1], self.peer_public_key_x)

    @property
    def pka(self) -> bytes:
        return self.pkx[0 if self.role == BLE_ROLE_CENTRAL else 1]

    @property
    def pkb(self) -> bytes:
        return self.pkx[0 if self.role == BLE_ROLE_PERIPHERAL else 1]

    @property
    def nx(self) -> Tuple[bytes, bytes]:
        assert self.peer_random_value
        return (self.r, self.peer_random_value)

    @property
    def na(self) -> bytes:
        return self.nx[0 if self.role == BLE_ROLE_CENTRAL else 1]

    @property
    def nb(self) -> bytes:
        return self.nx[0 if self.role == BLE_ROLE_PERIPHERAL else 1]

    def send(self, handle: int, pkt: Packet):
        self.hci_dev.send_l2cap(handle=handle, cid=BLE_L2CAP_CID_SM, cmd=SM_Hdr() / pkt)

    def pair(self, handle: int):
        if self.role == BLE_ROLE_CENTRAL:
            pkt = SM_Pairing_Request(
                authentication=self.authreq,
                initiator_key_distribution=0x01,
                responder_key_distribution=0x01,
            )
            self.preq = pkt
            self.send(handle=handle, pkt=pkt)
        else:
            self.send(handle=handle, pkt=SM_Security_Request(authentication=self.authreq))

    def set_own_address(self, addr: str, address_type: int):
        addr = addr.replace(":", "")
        if self.role == BLE_ROLE_CENTRAL:
            self.ia = bytes.fromhex(addr)
            self.iat = address_type
        else:
            self.ra = bytes.fromhex(addr)
            self.rat = address_type

    def set_peer_address(self, addr: str, address_type: int):
        addr = addr.replace(":", "")

        if self.role == BLE_ROLE_CENTRAL:
            self.ra = bytes.fromhex(addr)
            self.rat = address_type
        else:
            self.ia = bytes.fromhex(addr)
            self.iat = address_type

    def on_message_rx(self, sock: BluetoothUserSocket, handle: int, pkt: Packet):
        if SM_Pairing_Request in pkt:
            logging.info("Received Pairing Request")
            self.on_pairing_request(sock, handle, pkt)
        elif SM_Pairing_Response in pkt:
            logging.info("Received Pairing Response")
            self.on_pairing_response(sock, handle, pkt)
        elif SM_Public_Key in pkt:
            logging.info("Received Public Key")
            self.on_public_key(sock, handle, pkt)
        elif SM_Confirm in pkt:
            logging.info("Received Confirm")
            self.on_confirm(sock, handle, pkt)
        elif SM_Random in pkt:
            logging.info("Received Random")
            self.on_pairing_random(sock, handle, pkt)
        elif SM_DHKey_Check in pkt:
            logging.info("Received DHKey Check")
            self.on_dhkey_check(sock, handle, pkt)

    def on_pairing_request(
        self, pkt: Packet
    ):
        if self.role == BLE_ROLE_CENTRAL:
            return
        
        self.preq = pkt.getlayer(SM_Pairing_Request)
        pair_rsp = SM_Pairing_Response(
            authentication=self.authreq,
            initiator_key_distribution=0x01,
            responder_key_distribution=0x01,
        )
        self.pres = pair_rsp
        # ACL Layer has connection handle, if does not work parse it before
        self.send(handle=pkt.handle, pkt=pair_rsp)

    def on_pairing_response(self, pkt: Packet):
        if self.role == BLE_ROLE_PERIPHERAL:
            return
        self.pres = pkt.getlayer(SM_Pairing_Response)
        self.send(
            handle=pkt.handle,
            pkt=SM_Public_Key(key_x=self.ecc_key.x[::-1], key_y=self.ecc_key.y[::-1]),
        )

    def on_public_key(self, pkt: Packet):

        self.peer_public_key_x = pkt.key_x
        self.peer_public_key_y = pkt.key_y

        self.dhkey = self.ecc_key.dh(pkt.key_x[::-1], pkt.key_y[::-1])[::-1]
        if self.role == BLE_ROLE_PERIPHERAL:
            # Need to compute DHKey
            self.send(
                handle=pkt.handle,
                pkt=SM_Public_Key(key_x=self.ecc_key.x[::-1], key_y=self.ecc_key.y[::-1]),
            )

            self.send(handle=pkt.handle, pkt = self.make_pairing_confirm())

    def make_pairing_confirm(self):
        self.r = r()
        if self.sc:
            z = 0  # JW only for now
            if self.role == BLE_ROLE_CENTRAL:
                confirm_value = f4(
                    self.pka, self.pkb, self.r, bytes([z])
                )  # pka, pkb, r, z
            else:
                confirm_value = f4(
                    self.pkb, self.pka, self.r, bytes([z])
                )  # pkb, pka, r, z

        return SM_Confirm(confirm=confirm_value)

    def on_confirm(self, pkt: Packet):
        if self.role == BLE_ROLE_CENTRAL:
            self.confirm_value = pkt.confirm
            self.r = r()
            self.send(handle=pkt.handle, pkt=SM_Random(random=self.r))
            # this is like this only because we are doing justworks

    # def make_pairing_random(self):
    #     return SM_Random(random=self.r)

    def on_pairing_random(self, pkt: Packet):
        self.peer_random_value = pkt.random
        if self.role == BLE_ROLE_CENTRAL:
            confirm_verify = f4(
                self.pkb, self.pka, pkt.random, bytes([0])
            )  # Valid for JW and NUMCMP
            if confirm_verify != self.confirm_value:
                self.send(handle=pkt.handle, pkt=SM_Failed(reason=0x04))

        a = self.ia[::-1] + bytes([self.iat])
        b = self.ra[::-1] + bytes([self.rat])

        (mac_key, self.ltk) = f5(self.dhkey, self.na, self.nb, a, b)

        # Only JW and NUMCMP
        ra = bytes(16)
        rb = ra

        assert self.preq and self.pres
        io_cap_a = bytes(
            [
                self.preq.iocap,
                self.preq.oob,
                self.preq.authentication,
            ]
        )
        io_cap_b = bytes(
            [
                self.pres.iocap,
                self.pres.oob,
                self.pres.authentication,
            ]
        )

        self.ea = f6(mac_key, self.na, self.nb, rb, io_cap_a, a, b)
        self.eb = f6(mac_key, self.nb, self.na, ra, io_cap_b, b, a)

        if self.role == BLE_ROLE_CENTRAL:
            self.send( handle=pkt.handle, pkt=SM_DHKey_Check(dhkey_check=self.ea))
        else:
            self.send( handle=pkt.handle, pkt=SM_Random(random=self.r))

    def on_dhkey_check(self, pkt: Packet):
        expected = self.eb if self.role == BLE_ROLE_CENTRAL else self.ea

        if pkt.dhkey_check != expected:
            logging.warning("DHKey Check failed")
            self.send(handle=pkt.handle, pkt=SM_Failed(reason=11))

        if self.role == BLE_ROLE_CENTRAL:
            # Central starts encryption
            self.hci_dev.send_command(HCI_Cmd_LE_Enable_Encryption(
                    handle=pkt.handle,
                    ltk=self.ltk,
                ))
        else:
            # Peripheral sends dhkey check and waits for controller to ask for LTK
            self.send(handle=pkt.handle, pkt=SM_DHKey_Check(dhkey_check=self.eb))
            cmd = self.hci_dev.wait_event(HCI_LE_Meta_Long_Term_Key_Request)
            assert self.ltk is not None
            self.hci_dev.send_command(HCI_Cmd_LE_Long_Term_Key_Request_Reply(handle=cmd.handle, ltk=self.ltk))
            logging.info("Pairing complete")
