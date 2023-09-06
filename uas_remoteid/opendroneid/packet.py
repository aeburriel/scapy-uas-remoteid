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


from scapy.packet import Packet
from scapy.fields import (
    BitEnumField,
    BitField,
    ByteField,
    ByteEnumField,
    ConditionalField,
    FieldLenField,
    LEShortField,
    MultipleTypeField,
    PacketField,
    PacketListField,
    ScalingField,
    SignedByteField,
    StrFixedLenField,
    UUIDField,
    UTCTimeField,
)
from time import gmtime, time
from typing import (
    Optional,
    Tuple,
    Union,
)


# Custom Fields
class BaseNumericField:
    def __init__(self, name, default):
        super().__init__(name, default)

    def i2h(self, pkt: Packet, x: int) -> float:
        data = super().i2h(pkt, x)
        return self._decode(data)

    def h2i(self, pkt: Packet, x: Union[float, int]) -> int:
        if x is None:
            value = None
        else:
            value = self._encode(x)
        return super().h2i(pkt, value)


class AltitudeField(ScalingField):
    def __init__(self, name: str, default: float):
        ScalingField.__init__(self, name, default,
                              scaling=0.5, offset=-1000.0, unit="m", fmt="<H")


class DecimalDegreeField(ScalingField):
    def __init__(self, name: str, default: float):
        ScalingField.__init__(self, name, default,
                              scaling=1E-7, ndigits=10, unit="°", fmt="<i")


class DirectionField(ByteField):
    __slots__ = ["sign_name"]

    @staticmethod
    def _decode(directionByte: int, directionSign: int) -> float:
        if directionSign:
            return directionByte + 180.0
        else:
            return float(directionByte)

    @staticmethod
    def _encode(direction: float) -> Tuple[int, int]:
        directionByte = int(round(direction))
        directionSign = directionByte >= 180.0
        if directionSign:
            directionByte -= 180

        return (directionByte, directionSign)

    def __init__(self, name: str, sign_name: str,
                 default: Optional[float] = None):
        self.sign_name = sign_name

        if default is not None:
            default, sign = self._encode(default)

        ByteField.__init__(self, name, default)

    def i2h(self, pkt: Packet, x: int) -> float:
        data = super().i2h(pkt, x)
        return self._decode(data, pkt.getfieldval(self.sign_name))

    def h2i(self, pkt: Packet, x: float) -> int:
        value, sign = self._encode(x)
        if pkt is not None:
            pkt.setfieldval(self.sign_name, sign)

        return super().h2i(pkt, value)


class HorizontalSpeedField(ByteField):
    __slots__ = ["multiplier_name"]

    @staticmethod
    def _decode(speedByte: int, multiplierBit: int) -> float:
        if multiplierBit:
            return speedByte * 0.75 + 255.0 * 0.25
        else:
            return speedByte * 0.25

    @staticmethod
    def _encode(speed: float) -> Tuple[int, int]:
        if speed < 255.0 * 0.25:
            multiplierBit = 0
            speedByte = int(round(speed / 0.25))
        else:
            multiplierBit = 1
            value = (speed - (255.0 * 0.25)) / 0.75
            if value < 0.0:
                speedByte = 0
            elif value > 255.0:
                speedByte = 255
            else:
                speedByte = int(round(value))

        return (speedByte, multiplierBit)

    def __init__(self, name: str, multiplier_name: str,
                 default: Optional[float] = None):
        self.multiplier_name = multiplier_name
        ByteField.__init__(self, name, default)

    def i2h(self, pkt: Packet, x: int) -> float:
        data = super().i2h(pkt, x)
        return self._decode(data, pkt.getfieldval(self.multiplier_name))

    def h2i(self, pkt: Packet, x: float) -> int:
        value, multiplier = self._encode(x)
        if pkt is not None:
            pkt.setfieldval(self.multiplier_name, multiplier)

        return super().h2i(pkt, value)


class TimestampField(UTCTimeField):
    def __init__(self, name: str, default: int = time()):
        UTCTimeField.__init__(self, name, default,
                              epoch=gmtime(1546300800),
                              strf="%Y-%m-%d %H:%M:%S %Z",
                              fmt="<I")


class TimestampHourlyField(ScalingField):
    def __init__(self, name: str, default: float):
        ScalingField.__init__(self, name, default,
                              scaling=0.1, unit="s", fmt="<H")


class VerticalSpeedField(BaseNumericField, SignedByteField):
    @staticmethod
    def _decode(speedByte: int) -> float:
        return speedByte * 0.5

    @staticmethod
    def _encode(speed: float) -> int:
        data = speed * 2.0
        if data < -128.0:
            return -128
        elif data > 127.0:
            return 127

        return int(round(data))


# Constants
_AUTENTICATION_AUTH_TYPE = {
    0: "None",
    1: "UAS-ID",
    2: "Operator-ID",
    3: "Message-set",
    4: "Network remote-id",
    5: "Specific authentication",
    6: "Reserved for Spec 6",
    7: "Reserved for Spec 7",
    8: "Reserved for Spec 8",
    9: "Reserved for Spec 9",
    10: "Available for Private A",
    11: "Available for Private B",
    12: "Available for Private C",
    13: "Available for Private D",
    14: "Available for Private E",
    15: "Available for Private F",
}

_BASICID_ID_TYPE = {
    0: "None",
    1: "Serial Number (ANSI/CTA-2063-A)",
    2: "CAA Assigned ID",
    3: "UTM Assigned ID (UUID RFC4122)",
    4: "Specific Session ID"
}

# https://www.icao.int/airnavigation/IATF/Pages/ASTM-Remote-ID.aspx
_BASICID_SPECIFIC_SESSION_ID = {
    0: "Reserved",
    1: "IETF",
    2: "ASTM",
}

_BASICID_UAS_TYPE = {
    0: "None",
    1: "Fixed Wing Aeroplane",
    2: "Helicopter/Multirotor",
    3: "Gyroplane",
    4: "Hybrid Lift (fixed wing aircraft that can take off vertically)",
    5: "Ornithopter",
    6: "Glider",
    7: "Kite",
    8: "Free Balloon",
    9: "Captive Balloon",
    10: "Airship (such as a blimp)",
    11: "Free fall/Parachute (unpowered)",
    12: "Rocket",
    13: "Tethered Powered Aircraft",
    14: "Ground obstacle",
    15: "Other"
}

_LOCATION_EW_DIRECTION = {
    0: "East (<180)",
    1: "West (≥180)"
}

_LOCATION_HEIGHT_TYPE = {
    0: "Reference over takeoff",
    1: "Reference over ground"
}

_LOCATION_HORIZONTAL_ACCURACY = {
    0: "≥18.52km (10NM) or Unknown",
    1: "<18.52km (10NM)",
    2: "<7.408km (4NM)",
    3: "<3.704km (2NM)",
    4: "<1852m (1NM)",
    5: "<926m (0.5NM)",
    6: "<555.6m (0.3NM)",
    7: "<185.2m (0.1NM)",
    8: "<92.6m (0.05NM)",
    9: "<30m",
    10: "<10m",
    11: "<3m",
    12: "<1m",
    13: "Reserved",
    14: "Reserved",
    15: "Reserved",
}

_LOCATION_SPEED_ACCURACY = {
    0: "≥10m/s or Unknown",
    1: "<10m/s",
    2: "<3m/s",
    3: "<1m/s",
    4: "<0.3m/s"
}

_LOCATION_SPEED_MULTIPLIER = {
    0: "x0.25",
    1: "x0.75"
}

_LOCATION_STATUS = {
    0: "Undeclared",
    1: "On Ground",
    2: "Airbone",
    3: "Emergency",
    4: "Remote-ID system failure"
}

_LOCATION_TSA_ACCURACY = {0: "Unknown"} | {
    x: f"±{x / 10:0.1f}s" for x in range(1, 16)
}

_LOCATION_VERTICAL_ACCURACY = {
    0: "≥150m or Unknown",
    1: "<150m",
    2: "<45m",
    3: "<25m",
    4: "<10m",
    5: "<3m",
    6: "<1m",
    7: "Reserved"
}

_OPERATORID_OPERATORID_TYPE = {0: "Operator ID"} | {
    x: f"Reserved {x}" for x in range(1, 201)
} | {
    x: f"Available for private use {x}" for x in range(201, 256)
}

_REMOTEID_PROTO_VERSION = {
    0: "F3411-19 (1.0)",
    1: "F3411-20 (1.1)",
    2: "F3411-22 (2.0)",
    15: "Reserved for Private Use"
}

_SELFID_DESC_TYPE = {
    0: "Text Description",
    1: "Emergency Description",
    2: "Extended Status Description"
}

_SYSTEM_CLASSIFICATION_TYPE = {
    0: "Undeclared",
    1: "European Union",
    2: "Reserved 2",
    3: "Reserved 3",
    4: "Reserved 4",
    5: "Reserved 5",
    6: "Reserved 6",
    7: "Reserved 7",
}

_SYSTEM_OPERATOR_LOCATION_TYPE = {
    0: "Takeoff",
    1: "Live GNSS",
    2: "Fixed",
    3: "Reserved"
}

_SYSTEM_CATEGORY_EU = {
    0: "Undeclared",
    1: "Open",
    2: "Specific",
    3: "Certified"
}

_SYSTEM_CLASS_EU = {
    0: "Undeclared",
    1: "Class 0",
    2: "Class 1",
    3: "Class 2",
    4: "Class 3",
    5: "Class 4",
    6: "Class 5",
    7: "Class 6"
}


# Packets

class OpenDroneIDPacket(Packet):
    name = "OpenDroneID"
    fields_desc = [
        BitField("messageType", 5, 4),
        BitEnumField("protoVersion", 2, 4, _REMOTEID_PROTO_VERSION),

        StrFixedLenField("data", "", 24)
    ]

    _parsers = {}

    @classmethod
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._parsers[cls.messageType.default] = cls

    @classmethod
    def dispatch_hook(cls, _pkt=None, *args, **kwargs):
        if _pkt is None:
            return cls
        return OpenDroneIDPacket.guess_payload_class(_pkt, args, kwargs)

    @classmethod
    def guess_payload(cls, payload, **kwargs):
        return cls.guess_payload_class(payload, **kwargs)(payload)

    @classmethod
    def guess_payload_class(cls, payload, *args, **kwargs):
        message_type = payload[0] >> 4
        return cls._parsers.get(message_type, OpenDroneIDPacket)

    def extract_padding(self, s):
        return "", s


class BasicID(OpenDroneIDPacket):
    name = "OpenDroneID Basic-ID"
    match_subclass = True
    fields_desc = [
        BitField("messageType", 0, 4),
        BitEnumField("protoVersion", 2, 4, _REMOTEID_PROTO_VERSION),

        BitEnumField("idType", None, 4, _BASICID_ID_TYPE),
        BitEnumField("uasType", None, 4, _BASICID_UAS_TYPE),

        ConditionalField(
            ByteEnumField("ssi", 0, _BASICID_SPECIFIC_SESSION_ID),
            lambda pkt: pkt.idType == 4
        ),
        MultipleTypeField(
            [
                (UUIDField("uasId", None),
                    lambda pkt: pkt.idType == 3),
                (StrFixedLenField("uasId", "", 19),
                    lambda pkt: pkt.idType == 4),
            ],
            StrFixedLenField("uasId", "", length=20)
        ),
        ConditionalField(
            StrFixedLenField("uasId_pad", "", 4), lambda pkt: pkt.idType == 3
        ),

        StrFixedLenField("reserved", "", 3)
    ]


class Location(OpenDroneIDPacket):
    name = "OpenDroneID Location"
    match_subclass = True
    fields_desc = [
        BitField("messageType", 1, 4),
        BitEnumField("protoVersion", 2, 4, _REMOTEID_PROTO_VERSION),

        BitEnumField("status", 0, 4, _LOCATION_STATUS),
        BitField("reserved", 0, 1),
        BitEnumField("heightType", 0, 1, _LOCATION_HEIGHT_TYPE),
        BitEnumField("ewDirection", 0, 1, _LOCATION_EW_DIRECTION),
        BitEnumField("speedMult", 0, 1, _LOCATION_SPEED_MULTIPLIER),
        DirectionField("direction", "ewDirection", 0),
        HorizontalSpeedField("speedHorizontal", "speedMult", 0),
        VerticalSpeedField("speedVertical", 0),
        DecimalDegreeField("latitude", 0),
        DecimalDegreeField("longitude", 0),
        AltitudeField("altitudeBaro", 0),
        AltitudeField("altitudeGeo", 0),
        AltitudeField("height", 0),
        BitEnumField("vertAccuracy", 0, 4, _LOCATION_VERTICAL_ACCURACY),
        BitEnumField("horizAccuracy", 0, 4, _LOCATION_HORIZONTAL_ACCURACY),
        BitEnumField("baroAccuracy", 0, 4, _LOCATION_VERTICAL_ACCURACY),
        BitEnumField("speedAccuracy", 0, 4, _LOCATION_SPEED_ACCURACY),
        TimestampHourlyField("timeStamp", b"\xff\xff"),
        BitField("reserved2", 0, 4),
        BitEnumField("tsaAccuracy", 0, 4, _LOCATION_TSA_ACCURACY),
        ByteField("reserved3", 0)
    ]


class Authentication(OpenDroneIDPacket):
    name = "OpenDroneID Authentication"
    match_subclass = True
    fields_desc = [
        BitField("messageType", 2, 4),
        BitEnumField("protoVersion", 2, 4, _REMOTEID_PROTO_VERSION),

        BitEnumField("authType", 0, 4, _AUTENTICATION_AUTH_TYPE),
        BitField("dataPage", 0, 4),

        ConditionalField(
            ByteField("lastPageIndex", 0),
            lambda pkt: pkt.dataPage == 0
        ),
        ConditionalField(
            ByteField("length", 0),
            lambda pkt: pkt.dataPage == 0
        ),
        ConditionalField(
            TimestampField("timestamp", time()),
            lambda pkt: pkt.dataPage == 0
        ),
        ConditionalField(
            StrFixedLenField("authData0", "", 17),
            lambda pkt: pkt.dataPage == 0
        ),

        ConditionalField(
            StrFixedLenField("authData", "", 23),
            lambda pkt: pkt.dataPage > 0
        )
    ]


class SelfID(OpenDroneIDPacket):
    name = "OpenDroneID Self-ID"
    match_subclass = True
    fields_desc = [
        BitField("messageType", 3, 4),
        BitEnumField("protoVersion", 2, 4, _REMOTEID_PROTO_VERSION),

        ByteEnumField("descType", 0, _SELFID_DESC_TYPE),
        StrFixedLenField("desc", "", 23)
    ]


class System(OpenDroneIDPacket):
    name = "OpenDroneID System"
    match_subclass = True
    fields_desc = [
        BitField("messageType", 4, 4),
        BitEnumField("protoVersion", 2, 4, _REMOTEID_PROTO_VERSION),

        ConditionalField(
            BitField("reserved", 0, 6),
            lambda pkt: pkt.protoVersion == 0
        ),

        ConditionalField(
            BitField("reserved2", 0, 3),
            lambda pkt: pkt.protoVersion >= 1
        ),
        ConditionalField(
            BitEnumField("classificationType", 0, 3,
                         _SYSTEM_CLASSIFICATION_TYPE),
            lambda pkt: pkt.protoVersion >= 1
        ),

        BitEnumField("operatorLocationType", 0, 2,
                     _SYSTEM_OPERATOR_LOCATION_TYPE),

        DecimalDegreeField("operatorLatitude", 0),
        DecimalDegreeField("operatorLongitude", 0),
        LEShortField("areaCount", 0),
        ByteField("areaRadius", 0),
        LEShortField("areaCeiling", 0),
        LEShortField("areaFloor", 0),

        ConditionalField(
            StrFixedLenField("reserved3", "", 8),
            lambda pkt: pkt.protoVersion == 0
        ),

        ConditionalField(
            BitEnumField("categoryEU", 0, 4, _SYSTEM_CATEGORY_EU),
            lambda pkt: pkt.protoVersion >= 1 and pkt.classificationType == 1
        ),
        ConditionalField(
            BitEnumField("classEU", 0, 4, _SYSTEM_CLASS_EU),
            lambda pkt: pkt.protoVersion >= 1 and pkt.classificationType == 1
        ),

        ConditionalField(
            ByteField("category", 0),
            lambda pkt: pkt.protoVersion >= 1 and pkt.classificationType != 1
        ),

        ConditionalField(
            AltitudeField("operatorAltitudeGeo", 0),
            lambda pkt: pkt.protoVersion >= 1
        ),
        ConditionalField(
            TimestampField("timestamp", time()),
            lambda pkt: pkt.protoVersion >= 1
        ),
        ConditionalField(
            ByteField("reserved4", 0),
            lambda pkt: pkt.protoVersion >= 1
        )
    ]


class OperatorID(OpenDroneIDPacket):
    name = "OpenDroneID Operator-ID"
    match_subclass = True
    fields_desc = [
        BitField("messageType", 5, 4),
        BitEnumField("protoVersion", 2, 4, _REMOTEID_PROTO_VERSION),

        ByteEnumField("operatorIdType", 0, _OPERATORID_OPERATORID_TYPE),
        StrFixedLenField("operatorId", "", 20),
        StrFixedLenField("reserved", "", 3)
    ]


class MessagePack(OpenDroneIDPacket):
    name = "OpenDroneID MessagePack"
    fields_desc = [
        BitField("messageType", 15, 4),
        BitEnumField("protoVersion", 2, 4, _REMOTEID_PROTO_VERSION),

        ByteField("length", 25),
        FieldLenField("quantity", None, fmt="B", count_of="data"),
        PacketListField(
            "data", [], OpenDroneIDPacket.guess_payload,
            count_from=lambda pkt: pkt.quantity
        )
    ]


class Bluetooth_OpenDroneID(Packet):
    name = "Bluetooth OpenDroneID"
    fields_desc = [
        ByteField("appCode", 0x0d),
        ByteField("counter", 0),
        PacketField("info", None, OpenDroneIDPacket)
    ]
