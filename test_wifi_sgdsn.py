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


from uas_remoteid.common.wifi import parse_dot11
from scapy.layers.dot11 import Dot11

# https://gitlab.com/wireshark/wireshark/-/merge_requests/1705
wifipkt = \
    b"\x80\x00\x00\x00\xff\xff\xff\xff\xff\xff\x60\x60\x1f\x09\x73\x68" \
    b"\x60\x60\x1f\x09\x73\x68\x00\x00" \
    b"\x2a\xe9\x35\x02\x00\x00\x00\x00\x80\x02\x20\x04\x00\x17\x44\x4a" \
    b"\x49\x2d\x31\x35\x38\x31\x45\x30\x4d\x36\x44\x46\x37\x37\x30\x30" \
    b"\x31\x31\x39\x42\x59\xdd\x43\x6a\x5c\x35\x01\x01\x01\x01\x03\x13" \
    b"\x31\x35\x38\x31\x45\x30\x4d\x36\x44\x46\x37\x37\x30\x30\x31\x31" \
    b"\x39\x42\x59\x04\x04\x00\x43\x0f\xd5\x05\x04\x00\x07\x5a\x4f\x06" \
    b"\x02\x00\x25\x07\x02\x00\x11\x08\x04\x00\x43\x0f\xde\x09\x04\x00" \
    b"\x07\x5a\x57\x0a\x01\x01\x0b\x02\x01\x4b"


if __name__ == "__main__":
    for packet in [
        wifipkt,
    ]:
        for msg in parse_dot11(Dot11(packet)):
            msg.show()
            dc = msg.toDataclass()
            print(dc)
