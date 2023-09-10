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


from math import pi
from scapy.packet import Packet
from scapy.fields import (
    BitField,
    ByteField,
    ByteEnumField,
    ConditionalField,
    FieldLenField,
    LEShortField,
    ScalingField,
    StrFixedLenField,
    UTCTimeField,
    X3BytesField,
)
from time import time


class DecimalDegreeField(ScalingField):
    def __init__(self, name: str, default: float):
        ScalingField.__init__(self, name, default,
                              scaling=1E-7 * 180.0 / pi, ndigits=10,
                              unit="°", fmt="<i")


class HeightField(ScalingField):
    def __init__(self, name: str, default: float):
        ScalingField.__init__(self, name, default,
                              scaling=0.1, ndigits=2, unit="m", fmt="<h")


class AngleField(ScalingField):
    def __init__(self, name: str, default: float):
        ScalingField.__init__(self, name, default,
                              scaling=0.01, offset=180.0,
                              ndigits=2, unit="°", fmt="<h")


class SpeedField(ScalingField):
    def __init__(self, name: str, default: float):
        ScalingField.__init__(self, name, default,
                              scaling=0.01, ndigits=3, unit="m/s", fmt="<H")


class TimestampField(UTCTimeField):
    def __init__(self, name: str, default: int = time()):
        UTCTimeField.__init__(self, name, default,
                              use_msec=True,
                              strf="%Y-%m-%d %H:%M:%S %Z",
                              fmt="<Q")


# Constants

# 2023-08-25 13:04:58 UTC
# https://mydjiflight.dji.com/links/links/areoscope_type
_DJI_PRODUCT_TYPE = {
    1: "Inspire 1",
    2: "Phantom 3 Series",
    3: "Phantom 3 Series",
    4: "Phantom 3 Std",
    5: "M100",
    6: "ACEONE",
    7: "WKM",
    8: "NAZA",
    9: "A2",
    10: "A3",
    11: "Phantom 4",
    12: "MG1",
    14: "M600",
    15: "Phantom 3 4k",
    16: "Mavic Pro",
    17: "Inspire 2",
    18: "Phantom 4 Pro",
    20: "N2",
    21: "Spark",
    23: "M600 Pro",
    24: "Mavic Air",
    25: "M200",
    26: "Phantom 4 Series",
    27: "Phantom 4 Adv",
    28: "M210",
    30: "M210RTK",
    31: "A3_AG",
    32: "MG2",
    34: "MG1A",
    35: "Phantom 4 RTK",
    36: "Phantom 4 Pro V2.0",
    38: "MG1P",
    40: "MG1P-RTK",
    41: "Mavic 2",
    44: "M200 V2 Series",
    51: "Mavic 2 Enterprise",
    53: "Mavic Mini",
    58: "Mavic Air 2",
    59: "P4M",
    60: "M300 RTK",
    61: "DJI FPV",
    63: "Mini 2",
    64: "AGRAS T10",
    65: "AGRAS T30",
    66: "Air 2S",
    67: "M30",
    68: "Mavic 3",
    69: "Mavic 2 Enterprise Advanced",
    70: "Mini SE",
    72: "AGRAS T40",
    73: "Mini 3 Pro",
    75: "DJI Avata",
    76: "DJI Inspire 3",
    77: "Mavic 3 Enterprise E/T/M",
    78: "DJI Flycart 30",
    82: "AGRAS T25",
    83: "AGRAS T50",
    84: "DJI Mavic 3 Pro",
    86: "DJI Mavic 3 Classic",
    87: "DJI Mini 3",
    88: "DJI Mini 2 SE",
    89: "M350 RTK",
    90: "DJI Air 3"
}

_DJI_TYPE = {
    0x10: "Flight info",
    0x11: "Flight purpose",
}


# Packets

class DJIPacket(Packet):
    name = "DJI"
    fields_desc = [
        X3BytesField("id", 0x586213)
    ]

    _parsers = {}

    @classmethod
    def __init_subclass__(cls, **kwargs):
        super().__init_subclass__(**kwargs)
        cls._parsers[cls.type.default] = cls

    def guess_payload_class(self, payload: bytes):
        return self._parsers.get(payload[0], None)


class FlightInfo(DJIPacket):
    name = "DJI Flight Reg Info"
    match_subclass = True
    fields_desc = [
        # https://github.com/kismetwireless/kismet/blob/master/dot11_parsers/dot11_ie_221_dji_droneid.cc
        ByteEnumField("type", 0x10, _DJI_TYPE),
        ByteField("version", 1),
        LEShortField("seqnum", None),

        BitField("unknown", 0, 4, tot_size=-2),
        BitField("pitchrollValid", 0, 1),
        BitField("vupValid", 0, 1),
        BitField("horizValid", 0, 1),
        BitField("heightValid", 0, 1),
        BitField("altValid", 0, 1),
        BitField("gpsValid", 0, 1),
        BitField("airbone", 0, 1),      # AKA: groundOrSky
        BitField("motorOn", 0, 1),
        BitField("uuidSet", 0, 1),
        BitField("homepointSet", 0, 1),
        BitField("userPrivateDisabled", 0, 1),
        BitField("serialValid", 0, 1, end_tot_size=-2),

        StrFixedLenField("sn", "", 16),
        DecimalDegreeField("longitude", 0),
        DecimalDegreeField("latitude", 0),
        HeightField("altitude", 0),     # AKA: absoluteHeight
        HeightField("height", 0),       # AKA: relativeHeight
        SpeedField("xSpeed", 0),
        SpeedField("ySpeed", 0),
        SpeedField("zSpeed", 0),

        ConditionalField(AngleField("pitch", 0),
                         lambda pkt: pkt.version == 1),
        ConditionalField(AngleField("roll", 0),
                         lambda pkt: pkt.version == 1),

        AngleField("yaw", 0),

        ConditionalField(TimestampField("personLocUpdateTime", 0),
                         lambda pkt: pkt.version == 2),

        ConditionalField(DecimalDegreeField("personLatitude", 0),
                         lambda pkt: pkt.version == 2),
        ConditionalField(DecimalDegreeField("personLongitude", 0),
                         lambda pkt: pkt.version == 2),
        DecimalDegreeField("homeLongitude", 0),
        DecimalDegreeField("homeLatitude", 0),

        ByteEnumField("produtType", 0, _DJI_PRODUCT_TYPE),
        FieldLenField("uuidLength", None, length_of="uuid", fmt="B"),
        StrFixedLenField("uuid", "", 20)
    ]


class FlightPurpose(DJIPacket):
    name = "DJI Flight Purpose"
    match_subclass = True
    fields_desc = [
        ByteEnumField("type", 0x11, _DJI_TYPE),
        StrFixedLenField("sn", "", 16),
        FieldLenField("planLen", None, length_of="plan", fmt="B"),
        StrFixedLenField("plan", "",
                         length_from=lambda pkt: max(100, pkt.planLen))
    ]
