import uuid
import sqlite3
import pickle
import time

internalDBFile = """C:\\Windows\\LTSvc\\probeinternal.db"""

class networkDevice:
    def __init__(self, deviceMac='zz-zz-zz-zz'):
        self.ip='0.0.0.0'
        self.hostname=''
        self.mac=deviceMac
        self.ports=[]
        self.commstrings=[]
    def setIP(self, ip):
        self.ip=ip
    def setHostname(self, hostname):
        self.hostname=hostname
    def setMac(self, mac):
        self.mac=mac
    def setPort(self, ports):
        self.ports=ports
    def addCommString(self, communityString):
        self.commstrings.append(communityString)
    def setCommStrings(self, communityStrings):
        self.commstrings=communityStrings
    def copyDevice(self, newDevice):
        self.ip=newDevice.ip
        self.hostname=newDevice.hostname
        self.mac=newDevice.mac
        self.ports=newDevice.ports
        self.commstrings=newDevice.commstrings
    def getContents(self):
        return self.__dict__

conn = sqlite3.connect(internalDBFile)
c = conn.cursor()
c.execute("""CREATE TABLE IF NOT EXISTS `networkdevices` (deviceMAC text PRIMARY KEY, pickledNetworkDevice text, checkForOffline int, lastUpdate int);""")

for i in range(100):
    newNetworkDevice = networkDevice(str(uuid.uuid4()))
    newNetworkDevice.setPort('80')
    newNetworkDevice.addCommString('public')
    newNetworkDevice.setHostname(str(uuid.uuid4()))
    newNetworkDevice.setIP('192.168.1.%s'%i)
    pnewNetworkDevice = pickle.dumps(newNetworkDevice)
    storeDate = int(time.time())
    c.execute("""INSERT OR REPLACE INTO `networkdevices` (deviceMAC, pickledNetworkDevice, checkForOffline, lastUpdate)
                        VALUES (?, ?, ?, ?);""",
                      (newNetworkDevice.mac,pnewNetworkDevice,1,storeDate))
conn.commit()
conn.close()
