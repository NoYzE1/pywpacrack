# pywpacrack
WPA Cracker in Python3

-- Proof of Concept --

The File with the Data must have following Format:

ap essid<br>
ap mac<br>
sp mac<br>
ap nonce<br>
sp nonce<br>
eapol data<br>
mic of frame 2<br>

Format like a2f5g3dda2b5 -> Hex without seperators

For now the Data has to be extracted from the pcap manually.
I'll look into a parser for the handshake in the future.
