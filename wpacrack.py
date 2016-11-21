import hashlib
import hmac
import sys
import time

f = open("{0}".format(sys.argv[1]), "r")

passwords = open("{0}".format(sys.argv[2]), "r")

class Data:
    essid = f.readline().strip("\n")
    amacstr = f.readline()
    amac = []
    smacstr = f.readline()
    smac = []
    anoncestr = f.readline()
    anonce = []
    snoncestr = f.readline()
    snonce = []
    datastr = f.readline()
    micstr = f.readline()
    mic = []
    cmik = b''
    data = []
    pmk = b''

def str_to_hex(string):
    string = string.strip("\n")
    hexarr = []
    for i in range(0, len(string), 2):
        hexarr.append(int(string[i:i+2], 16))
    return hexarr

def process_data(datastr):
    datastr = datastr.strip("\n")
    data = []
    datahex = []
    for i in range(0, len(datastr), 2):
        data.append(int(datastr[i:i+2], 16))
    for i in range(81, 98, 1):
        data[i] = 0
    return data

def bytes_to_hex(b):
    h = ""
    for i in range(len(b)):
        h += hex(b[i]).strip("0x")
    return h

# Calculate Pairwise Master Key
def calculate_PMK(password, essid):
    return hashlib.pbkdf2_hmac("sha1", bytes(password, "utf-8"), bytes(essid, "utf-8"), 4096, 32)

# Calculate Pairwise Transient Key
def calculate_PTK(amac, smac, anonce, snonce, pmk):

    ptk = b''

    # Pairwise Key Expansion
    pke = [0x50, 0x61, 0x69, 0x72, 0x77, 0x69, 0x73, 0x65, 0x20, 0x6b, 0x65, 0x79, 0x20, 0x65, 0x78, 0x70, 0x61, 0x6e, 0x73, 0x69, 0x6f, 0x6e, 0x00]
    pke += min(amac, smac)
    pke += max(amac, smac)
    pke += min(anonce, snonce)
    pke += max(anonce, snonce)
    pke.append(0x00)

    for i in range(4):
        pke[99] = i;
        ptk += hmac.new(pmk, bytes(pke), "sha1").digest()
    return ptk

def calculate_MIC(ptk, data):
    data = bytes(data)
    h = hashlib.sha1()
    return hmac.new(ptk[0:16], data, "sha1").digest()[0:16]

def calculate(password):
    pmk = calculate_PMK(password, Data.essid)
    ptk = calculate_PTK(Data.amac, Data.smac, Data.anonce, Data.snonce, pmk)
    cmic = calculate_MIC(ptk, Data.data)
    return pmk, ptk, cmic

Data.amac = str_to_hex(Data.amacstr)
Data.smac = str_to_hex(Data.smacstr)
Data.anonce = str_to_hex(Data.anoncestr)
Data.snonce = str_to_hex(Data.snoncestr)
Data.mic = str_to_hex(Data.micstr)
Data.mic = bytes(Data.mic)
Data.data = process_data(Data.datastr)

counter = 0
kps_counter = 0
kps = 0
ts = time.time()
ts2 = time.time()

while True:
    password = passwords.readline().strip("\n")
    if password != "":
        counter += 1
        pmk, ptk, cmic = calculate(password)
        if time.time() - ts >= 1:
            kps = counter - kps_counter
            kps_counter = counter
            ts = time.time()
        if time.time() - ts2 >= 0.05:
            print("Keys tested: {0} ({1} k/s)".format(counter, kps))
            print("Current Passphrase: {0}".format(password))
            print("Master Key: ", bytes_to_hex(pmk))
            print("Transient Key: ", bytes_to_hex(ptk))
            print("Message Integrity Check: ", bytes_to_hex(cmic))
            print()
            ts2 = time.time()
        if cmic == Data.mic:
            print("Key found! [ {0} ]".format(password))
            exit(0)
    else:
        print("Passphrase not in Dictionary!")
        break
