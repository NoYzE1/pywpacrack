# pywpacrack
WPA Cracker in Python3

-- Proof of Concept --

The File with the Data must have following Format:

<ap essid>
<ap mac>
<sp mac>
<ap nonce>
<sp nonce>
<eapol data>
<mic of frame 2>

Format like a2f5g3dda2b5 -> Hex without seperators

For now the Data has to be extracted from the pcap manually.
I'll look into a parser for the handshake in the future.
