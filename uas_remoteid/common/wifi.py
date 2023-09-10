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


from ..dji.packet import DJIPacket
from ..opendroneid.packet import (
    Legacy_OpenDroneID,
    OpenDroneIDPacket,
)
from scapy.fields import (
    ByteField,
    LEShortField,
    OUIField,
    PacketListField,
    StrFixedLenField,
    StrLenField,
    XByteField,
)
from scapy.layers.dot11 import (
    Dot11,
    Dot11EltVendorSpecific,
    bind_layers,
)
from scapy.packet import Packet
from typing import Generator


def attr_guess_payload(payload, **kargs):
    dissectors = {
        0x03: Dot11NAN_ServiceDescriptorAttribute
    }
    return dissectors.get(payload[0], Dot11NAN_UnknownAttribute)(payload)


class Dot11NAN_Attribute(Packet):
    def extract_padding(self, s):
        return "", s


class Dot11NAN_UnknownAttribute(Dot11NAN_Attribute):
    name = "NAN Unparsed Attribute"
    fields_desc = [
        XByteField("ID", None),
        LEShortField("length", None),
        StrLenField("info", "", length_from=lambda pkt: pkt.length)
    ]


class Dot11NAN_ServiceDescriptorAttribute(Dot11NAN_Attribute):
    name = "NAN Service Descriptor Attribute"
    fields_desc = [
        XByteField("ID", 0x03),
        LEShortField("length", None),
        StrFixedLenField("serviceID", None, 6),
        ByteField("instanceID", None),
        ByteField("requestorInstanceID", None),
        ByteField("serviceControl", None),
        ByteField("serviceInfoLength", None),
        ByteField("messageCounter", 0),
        StrLenField("info", "", length_from=lambda pkt: pkt.length - 11)
    ]


class Dot11NAN_VendorSpecificPublicAction(Packet):
    name = "NAN Vendor Specific Public Action"
    fields_desc = [
        ByteField("caetgory", 4),
        ByteField("action", 9),
        OUIField("oui", 0x506f9a),
        ByteField("ouiType", 0x13),
        PacketListField("attrs", None, attr_guess_payload)
    ]


bind_layers(Dot11, Dot11NAN_VendorSpecificPublicAction, subtype=13, type=0)


def parse_dot11(dot11: Dot11) -> Generator[OpenDroneIDPacket, None, None]:
    if Dot11NAN_VendorSpecificPublicAction in dot11:
        packet = dot11[Dot11NAN_VendorSpecificPublicAction]
        while packet is not None:
            # 802.11 WIFI NAN Action
            for subpacket in packet.attrs:
                if (
                    isinstance(subpacket, Dot11NAN_ServiceDescriptorAttribute)
                    and subpacket.serviceID == b"\x88\x69\x19\x9d\x92\x09"
                ):
                    yield OpenDroneIDPacket(subpacket.info)

            packet = packet.payload.getlayer(
                Dot11NAN_VendorSpecificPublicAction
            )
    elif Dot11EltVendorSpecific in dot11:
        packet = dot11[Dot11EltVendorSpecific]
        while packet is not None:
            # 802.11 beacon
            if packet.ID == 221:
                if packet.oui == 0xfa0bbc and packet.info[3] == 0x0d:
                    yield Legacy_OpenDroneID(packet.info[3:]).info
                elif (
                        packet.oui == 0x263712
                        and packet.info[3:6] == b"\x58\x62\x13"
                ):
                    yield DJIPacket(packet.info[3:])
            packet = packet.payload.getlayer(Dot11EltVendorSpecific)
