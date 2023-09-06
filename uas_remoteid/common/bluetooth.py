# Copyright (C) 2023 Antonio Eugenio Burriel <aeburriel@gmail.com>
#
# This file is part of scapy-uas-remoteid.
#
# scapy-uas-remoteid is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# scapy-uas-remoteid is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with scapy-uas-remoteid.  If not, see <http://www.gnu.org/licenses/>.

from ..opendroneid.packet import Bluetooth_OpenDroneID, OpenDroneIDPacket
from scapy.layers.bluetooth import (
    EIR_Hdr,
    EIR_ServiceData16BitUUID,
    HCI_Command_Hdr,
    HCI_Event_LE_Meta,
    HCI_Hdr,
    LEMACField,
    PadField,
    bind_layers,
)
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteEnumField,
    ByteField,
    FieldLenField,
    LEShortField,
    PacketListField,
    SignedByteField,
)
from scapy.packet import Packet
from typing import Optional


class HCI_LE_Meta_Extended_Advertising_Report(Packet):
    name = "Extended Advertising Report"
    fields_desc = [
        BitField("reserved", 0, 9, tot_size=-2),
        BitEnumField("status", 0, 2, {
            0: "Complete",
            1: "Incomplete, more data to come",
            2: "Incomplete, data truncated, no more to come",
            3: "Reserved for future use"
        }),
        BitField("legacyPDU", 0, 1),
        BitField("scanResponse", 0, 1),
        BitField("directedAdvertising", 0, 1),
        BitField("scannableAdvertising", 0, 1),
        BitField("connectableAdvertising", 0, 1, end_tot_size=-2),
        ByteEnumField("atype", 0, {
            0: "Public Device Address",
            1: "Random Device Address",
            2: ("Public Identity Address "
                "(corresponds to Resolved Private Address)"),
            3: ("Random (static) Identity Address "
                "(corresponds to Resolved Private Address)"),
            255: "No address provided (anonymous advertisement)"
        }),
        LEMACField("addr", None),
        ByteEnumField("primaryPhy", 0, {
            1: "Advertiser PHY is LE 1M",
            3: "Advertiser PHY is LE Coded"
        }),
        ByteEnumField("secondaryPhy", 0, {
            0: "No packets on the secondary advertising channel",
            1: "Advertiser PHY is LE 1M",
            2: "Advertiser PHY is LE 2M",
            3: "Advertiser PHY is LE Coded"
        }),
        ByteField("ssid", 0xff),
        SignedByteField("txPower", 127),
        SignedByteField("rssi", 127),
        LEShortField("advertisingInterval", 0),
        ByteEnumField("datype", 0, {
            0: "Public Device Address",
            1: "Random Device Address",
            2: ("Public Identity Address "
                "(Corresponds to Resolved Private Address)"),
            3: ("Random (static) Identity Address "
                "(Corresponds to Resolved Private Address)"),
            254: "Random Device Address (Controller unable to resolve)"
        }),
        LEMACField("daddr", None),
        FieldLenField("len", None, length_of="data", fmt="B"),
        PacketListField("data", [], EIR_Hdr, length_from=lambda pkt:pkt.len),
    ]

    def extract_padding(self, s):
        return "", s


class HCI_LE_Meta_Extended_Advertising_Reports(Packet):
    name = "Extended Advertising Reports"
    fields_desc = [
        FieldLenField("len", None, count_of="reports", fmt="B"),
        PacketListField("reports", None,
                        HCI_LE_Meta_Extended_Advertising_Report,
                        count_from=lambda pkt:pkt.len)
    ]


class HCI_Cmd_LE_Set_Extended_Advertising_Data(Packet):
    name = "Bluetooth Low Energy Set Extended Advertising Data"
    fields_desc = [
        ByteField("handle", 1),
        ByteField("dataOperation", 3),
        ByteField("fragmentPreference", 1),
        ByteField("len", None),
        PadField(
            PacketListField("data", [], EIR_Hdr,
                            length_from=lambda pkt:pkt.len),
            align=31, padwith=b"\0"
        )
    ]


bind_layers(HCI_Command_Hdr, HCI_Cmd_LE_Set_Extended_Advertising_Data,
            opcode=0x2037)
bind_layers(HCI_Event_LE_Meta, HCI_LE_Meta_Extended_Advertising_Reports,
            event=0x0d)
bind_layers(EIR_ServiceData16BitUUID, Bluetooth_OpenDroneID,
            svc_uuid=0xfffa)


def parse_hci(hci: HCI_Hdr) -> Optional[OpenDroneIDPacket]:
    packet = hci.getlayer(Bluetooth_OpenDroneID)
    if packet is None or packet.appCode != 0x0d:
        return None

    return packet.info
