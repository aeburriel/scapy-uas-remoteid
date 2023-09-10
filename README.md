# scapy-uas-remoteid
This repository contains a Scapy dissector for the following UAS Remote ID protocols:
* ASTM F3411 UAS Remote ID protocol.
* DJI Remote ID

It started as a training for the popular packet manipulation library Scapy <https://github.com/secdev/scapy> and is greatly influenced by Open Drone ID project <https://github.com/opendroneid/>.

Presently, DJI support is experimental and further validation is required.
The following works are the foundation for this development:
* Anatomy of DJI’s Drone Identification Implementation, Department 13, 2017
* ESP8266 DJI DroneID Throwie & Metaexploit's DJI Drone Spoof, Kevin Finisterre, 2017 <https://github.com/DJISDKUser>
* DJI Drone ID Spoofer, Llorenç Romá, 2021 <https://github.com/llorencroma/DJIDroneIDspoofer>
