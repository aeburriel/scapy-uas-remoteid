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


from dataclasses import dataclass
from scapy.packet import Packet
from scapy.fields import (
    BoundStrLenField,
    ByteField,
    ByteEnumField,
    FieldLenField,
    PacketListField,
    ScalingField,
    StrFixedLenField,
)
from typing import Self


# Custom Fields

class AltitudeField(ScalingField):
    def __init__(self, name: str, default: float):
        ScalingField.__init__(self, name, default,
                              scaling=1.0, ndigits=0, unit="m", fmt=">h")


class BearingField(ScalingField):
    def __init__(self, name: str, default: float):
        ScalingField.__init__(self, name, default,
                              scaling=1.0, ndigits=0, unit="°", fmt=">H")


class DecimalDegreeField(ScalingField):
    def __init__(self, name: str, default: float):
        ScalingField.__init__(self, name, default,
                              scaling=1E-5, ndigits=10, unit="°", fmt=">i")


class GroundSpeedField(ScalingField):
    def __init__(self, name: str, default: float):
        ScalingField.__init__(self, name, default,
                              scaling=1, unit="m/s", fmt="B")


# Constants
_SGDSN_DATA_TYPES = {
    0: "Reserved for future use",
    1: "Protocol version",
    2: "FR Identifier",
    3: "ANSI/CTA-2063 UAS Identifier",
    4: "UAS latitude",
    5: "UAS longitude",
    6: "UAS alttiude",
    7: "UAS height",
    8: "Takeoff latitude",
    9: "Takeoff longitude",
    10: "Ground speed",
    11: "True bearing",
}


# Packets

@dataclass
class SGDSN_Message:
    version: int = 1

    uasId_FR_manufacturer: str = None
    uasId_FR_model: str = None
    uasId_FR: str = None

    uasId_ANSI: str = None

    uasLatitude: float = None
    uasLongitude: float = None
    uasAltitude: float = None
    uasHeight: float = None
    uasSpeed: float = None
    uasBearing: float = None

    takeoffLatitude: float = None
    takeoffLongitude: float = None


class SGDSN_TLV(Packet):
    name = "SGDSN TLV Packet"
    fields_desc = [
        ByteEnumField("type", 0, _SGDSN_DATA_TYPES),
        FieldLenField("len", None, length_of="value", fmt="B"),
        StrFixedLenField("value", "", length_from=lambda pkt: pkt.len)
    ]

    _parsers = {}

    @classmethod
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._parsers[cls.type.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        if _pkt is None:
            return cls
        return SGDSN_TLV.guess_payload_class(_pkt, args, kwargs)

    @classmethod
    def guess_payload(cls, payload, **kwargs):
        return cls.guess_payload_class(payload, **kwargs)(payload)

    @classmethod
    def guess_payload_class(cls, payload, *args, **kwargs):
        message_type = payload[0]
        return cls._parsers.get(message_type, SGDSN_TLV)

    def extract_padding(self, s):
        return "", s


class SGDSNPacket(Packet):
    name = "SGDSM ECOI1934044A Message"
    fields_desc = [
        ByteField("appCode", 0x01),
        PacketListField("data", [], SGDSN_TLV.guess_payload)
    ]

    @staticmethod
    def fromDataclass(data: SGDSN_Message) -> Self:
        packet = SGDSNPacket()

        if data.version is not None:
            packet.data.append(Version(value=data.version))

        if data.uasId_FR is not None and len(data.uasId_FR) == 30:
            packet.data.append(FRId(
                value=(data.uasId_FR_manufacturer +
                       data.uasId_FR_model +
                       data.uasId_FR)
            ))

        if data.uasId_ANSI is not None:
            packet.data.append(ANSIId(value=data.uasId_ANSI))

        if data.uasLatitude is not None:
            packet.data.append(UASLatitude(value=data.uasLatitude))
        if data.uasLongitude is not None:
            packet.data.append(UASLongitude(value=data.uasLongitude))
        if data.uasAltitude is not None:
            packet.data.append(UASAltitude(value=data.uasAltitude))
        if data.uasHeight is not None:
            packet.data.append(UASHeight(value=data.uasHeight))

        if data.takeoffLatitude is not None:
            packet.data.append(TakeoffLatitude(value=data.takeoffLatitude))
        if data.takeoffLongitude is not None:
            packet.data.append(TakeoffLongitude(value=data.takeoffLongitude))

        if data.uasSpeed is not None:
            packet.data.append(UASGroundspeed(value=data.uasSpeed))
        if data.uasBearing is not None:
            packet.data.append(UASTruebearing(value=data.uasBearing))

        return packet

    def toDataclass(self) -> SGDSN_Message:
        result = SGDSN_Message()

        for item in self.data:
            if isinstance(item, Version):
                result.version = item.value
            elif isinstance(item, FRId):
                result.uasId_FR_manufacturer = item.value[0:3]
                result.uasId_FR_model = item.value[3:6]
                result.uasId_FR = item.value[6:30]
            elif isinstance(item, ANSIId):
                result.uasId_id = item.value
            elif isinstance(item, UASLatitude):
                result.uasLatitude = item.value
            elif isinstance(item, UASLongitude):
                result.uasLongitude = item.value
            elif isinstance(item, UASAltitude):
                result.uasAltitude = item.value
            elif isinstance(item, UASHeight):
                result.uasHeight = item.value
            elif isinstance(item, TakeoffLatitude):
                result.takeoffLatitude = item.value
            elif isinstance(item, TakeoffLongitude):
                result.takeoffLongitude = item.value
            elif isinstance(item, UASGroundspeed):
                result.uasSpeed = item.value
            elif isinstance(item, UASTruebearing):
                result.uasBearing = item.value

        return result


class Version(SGDSN_TLV):
    name = "SGDSN Version"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 1, _SGDSN_DATA_TYPES),
        ByteField("len", 1),
        ByteField("value", 1)
    ]


class FRId(SGDSN_TLV):
    name = "SGDSN French UAS ID"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 2, _SGDSN_DATA_TYPES),
        ByteField("len", 30),
        StrFixedLenField("value", "", 30)
    ]


class ANSIId(SGDSN_TLV):
    name = "SGDSN ANSI/CTA-2063 UAS ID"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 3, _SGDSN_DATA_TYPES),
        FieldLenField("len", None, length_of="value", fmt="B"),
        BoundStrLenField("value", "", minlen=6, maxlen=20,
                         length_from=lambda pkt: pkt.len)
    ]


class UASLatitude(SGDSN_TLV):
    name = "SGDSN UAS Latitude"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 4, _SGDSN_DATA_TYPES),
        ByteField("len", 4),
        DecimalDegreeField("value", 0)
    ]


class UASLongitude(SGDSN_TLV):
    name = "SGDSN UAS Longitude"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 5, _SGDSN_DATA_TYPES),
        ByteField("len", 4),
        DecimalDegreeField("value", 0)
    ]


class UASAltitude(SGDSN_TLV):
    name = "SGDSN UAS Altitude"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 6, _SGDSN_DATA_TYPES),
        ByteField("len", 2),
        AltitudeField("value", 0)
    ]


class UASHeight(SGDSN_TLV):
    name = "SGDSN UAS Height"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 7, _SGDSN_DATA_TYPES),
        ByteField("len", 2),
        AltitudeField("value", 0)
    ]


class TakeoffLatitude(SGDSN_TLV):
    name = "SGDSN Takeoff Latitude"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 8, _SGDSN_DATA_TYPES),
        ByteField("len", 4),
        DecimalDegreeField("value", 0)
    ]


class TakeoffLongitude(SGDSN_TLV):
    name = "SGDSN Takeoff Longitude"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 9, _SGDSN_DATA_TYPES),
        ByteField("len", 4),
        DecimalDegreeField("value", 0)
    ]


class UASGroundspeed(SGDSN_TLV):
    name = "SGDSN UAS Groundspeed"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 10, _SGDSN_DATA_TYPES),
        ByteField("len", 1),
        GroundSpeedField("value", 0)
    ]


class UASTruebearing(SGDSN_TLV):
    name = "SGDSN UAS True Bearing"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 11, _SGDSN_DATA_TYPES),
        ByteField("len", 2),
        BearingField("value", 0)
    ]
