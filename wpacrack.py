import hashlib
import hmac
import sys
import time


class Data:

    # File Descriptors
    f = open(sys.argv[1], "r")
    p = open(sys.argv[2], "r")

    # File Data
    essid = f.readline().strip("\n")
    amacstr = f.readline()
    smacstr = f.readline()
    anoncestr = f.readline()
    snoncestr = f.readline()
    datastr = f.readline()
    micstr = f.readline()

    # Bytestrings
    amac = []
    smac = []
    anonce = []
    snonce = []
    mic = []
    data = []

    # Cycle Data
    counter = 0
    kps_counter = 0
    kps = 0
    ts = time.time()
    ts2 = time.time()

    report = False
    report_freq = 0


def str_to_hex(string):
    string = string.strip("\n")
    hexarr = []
    for i in range(0, len(string), 2):
        hexarr.append(int(string[i:i+2], 16))
    return hexarr


def process_data(datastr):
    datastr = datastr.strip("\n")
    data = []
    for i in range(0, len(datastr), 2):
        data.append(int(datastr[i:i+2], 16))
    for i in range(81, 98, 1):
        data[i] = 0
    return data


def bytes_to_hex(b):
    h = ""
    l = len(b)
    for i in range(l):
        cb = b[i]
        if cb < 16:
            h += "0"
        h += hex(cb)[2:l-1]
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
    Data.amac = str_to_hex(Data.amacstr)
    Data.smac = str_to_hex(Data.smacstr)
    Data.anonce = str_to_hex(Data.anoncestr)
    Data.snonce = str_to_hex(Data.snoncestr)
    Data.mic = str_to_hex(Data.micstr)
    Data.mic = bytes(Data.mic)
    Data.data = process_data(Data.datastr)
    Data.f.close()
    if len(sys.argv) == 5:
        if sys.argv[3] == "-r":
            Data.report = True
            Data.report_freq = int(sys.argv[4])


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
            if Data.report == True:
                so = open("report", "w")
                so.write("Keys tested: {0} ({1} k/s)\n".format(str(Data.counter), str(Data.kps)))
                so.write("Current Passphrase: {0}\n".format(password))
                so.write("Master Key: {0}\n".format(bytes_to_hex(pmk)))
                so.write("Transient Key: {0}\n".format(bytes_to_hex(ptk)))
                so.write("Message Integrity Check: {0}\n".format(bytes_to_hex(cmic)))
                so.write("Key found! [ {0} ]\n".format(password))
                so.close()
            exit(0)
        if Data.report == True and Data.counter % Data.report_freq == 0:
            so = open("report", "w")
            so.write("Keys tested: {0} ({1} k/s)\n".format(str(Data.counter), str(Data.kps)))
            so.write("Current Passphrase: {0}\n".format(password))
            so.write("Master Key: {0}\n".format(bytes_to_hex(pmk)))
            so.write("Transient Key: {0}\n".format(bytes_to_hex(ptk)))
            so.write("Message Integrity Check: {0}\n".format(bytes_to_hex(cmic)))
            so.close()
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
