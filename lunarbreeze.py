import thread
import threading
import socket
import shlex
import json
from subprocess import *
from time import *
import _winreg
import sqlite3
import cPickle as pickle
from collections import deque
import ctypes
from datetime import * # used in _scheduler

# For 'service' functionality
import win32service
import win32serviceutil
import servicemanager

# Non-native libraries for ICMP and SNMP
from pysnmp.entity.rfc3413.oneliner import cmdgen
import pyping

class lunarBreezeProbe:
    def __init__(self):

        # Shared Variables
        self.snmpPort = 161
        self.onlineCheckInterval = 30 # in seconds
        self.pingTimeOut = 1000 # in milliseconds, read from the reg in seconds and converted
        self.portTimeOut = .5 # in seconds
        self.snmpTimeOut = 1 # in seconds
        self.debug = True
        self.restartMe = False
        self.internalDBFile = """C:\\Windows\\LTSvc\\lbinternal.db"""
        self.knownDevices = [] # List of tuples containing known devices read from database or added by discovery
                               # (MAC, IP, instance of networkDevice, OfflineCheckFlag)
                               # OfflineCheckFlag = Whether ping monitoring is enabled of this device.
        self.devicestatuses = {} # key,value dicionary dict[ip] = status (0 or 1)
        self.configDumpFile = """C:\\Windows\\LTSvc\\lb_config_dump.txt"""

        self.registryBase = """Software\\LunarBreeze"""
        self.registryConfig = self.registryBase + """\\Config"""
        self.registryStatus = self.registryBase + """\\Status"""
        self.registryCommands = self.registryBase + """\\Commands"""
        
        # scanRange is a dictionary that takes the form of scanRange['start']=count
        self.scanRange = {}
        self.portList = []
        self.communityStringsList = []
        self.scan_threads_in_use=0 # The number of discovery threads in use - as determined by scrutineer thread
        
        self.CREATE_NO_WINDOW = 0x08000000

        #Discovery Specific Variables
 
        self.activeIPList = [] # List used to store found active IPs during the discovery process
        self.discoveryInProgress = False
        self.activeMACList = {} # Shared by threads to store MAC/IP association. Key is MAC, value is IP
        self.newDevices = {} # Dictionary to store an instance of a class (networkDevice) of a discovered active device during the discovery process.
        self.IPMACDict = {}
        self.foundDevices = [] # Ephemeral list used during the discovery process to store `networkDevice` objects until they are committed.
        self.discoveryStartTime = '00:00'
        self.discoveryEndTIme = '23:59'
        self.discoveryCheckFrequency = 60

        # Log file locations and variables

        self.probeoperationLog = """C:\\Windows\\LTsvc\\lb_error_log.txt"""
        self.discoveryLog = """C:\\Windows\\LTsvc\\lb_discovery_log.txt"""
        self.detectionLog = """C:\\Windows\\LTsvc\\lb_detection_log.txt"""
        self.collectionLog = """C:\\Windows\\LTsvc\\lb_collection_log.txt"""

        self.pendingLogList = deque() # This list will contain a tuple contisting of log type and message, to be processed FIFO

        # Log levels - default should be 1

        # 0 - None
        # 1 - Errors
        # 2 - Errors + Information
        # 3 - Errors + Information + DEV MODE

        self.probeoperationLogLevel = 1
        self.discoveryLogLevel = 1
        self.detectionLogLevel = 1
        self.collectionLogLevel = 1

        # Thread Control Variables

        self.terminateThreads = False
        self.threadmanager = lbThreadManager()

        # Troubleshooting variables

        self.procSource = []

        # Initialize the log handler
        thread.start_new_thread(self._logHandler, ())

        # Before starting probe-ish functions, make sure the appropriate files/keys are in place
        self._preStartupCheck()

        # Read the scan configuration from the registry and set interval variables as necessary.
        if self.probeoperationLogLevel > 1: self.pendingLogList.append(('Reading Scan Configuration',self.probeoperationLog))
        self._readScanParametersFromRegistry()

        # The maximum number of threads allotted to the discovery process - this value scales based on the number of ranges being scanned and the number of responding devices
        self.maxDiscThreads=threading.BoundedSemaphore(self._calculateDeviceScanCount())

        # Initial functions to run when probe service starts
        if self.probeoperationLogLevel > 1:  self.pendingLogList.append(('Starting self._commandHandler as new thread...',self.probeoperationLog))
        thread.start_new_thread(self._commandHandler, ())

        # Populate known devices from internal database
        self.readDevicesFromDatabase()

        # Start the device monitoring thread - this in turn will launch child threads to monitor up/down status on devices
        if self.probeoperationLogLevel > 1: self.pendingLogList.append(('Starting device monitoring...',self.probeoperationLog))
        thread.start_new_thread(self._monitorDevices,())

        # Start the thread that manages scheduled scans
        if self.probeoperationLogLevel > 1: self.pendingLogList.append(('Starting scan scheduler...',self.probeoperationLog))
        self.lunarScheduler = lunarScheduler(startTime=self.discoveryStartTime,
                                             endTime=self.discoveryEndTIme,
                                             runFrequency=self.discoveryCheckFrequency) # need to add in additional class constructor parameters
        self.lunarScheduler.setLogFile(self.pendingLogList)

    def _calculateDeviceScanCount(self):

        """This function returns the number of possible devices to be discovered given the scan range. Should return a positive integer."""
        
        return int(30)
        
    def runDiscovery(self):
        
        """This should be run as a thread. This thread will process each scan range serially."""

        self.discoveryInProgress = True

        if self.discoveryLogLevel>2: self.pendingLogList.append((self.scanRange.keys(),self.discoveryLog))

        for scanRange in self.scanRange.keys():
            self.runDiscoveryOnRange(scanRange)

        # Update registry to indicate that discovery has run
        try:
            if self.probeoperationLogLevel > 1: self.pendingLogList.append(("Inventory Updated. Switching flag in registry.",self.discoveryLog))
            labTechKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,self.registryStatus, 0, _winreg.KEY_ALL_ACCESS)
            _winreg.SetValueEx(labTechKey, 'InventoryUpdated', 0, _winreg.REG_SZ, '1')
        except WindowsError as registryerror:
            if self.probeoperationLogLevel > 0: self.pendingLogList.append(("Inventory Changed, but could not update key.\n%s"%registryerror,self.discoveryLog))

        self.discoveryInProgress = False
        
    def runDiscoveryOnRange(self, scanRangeKey): # as an argument pass the key for self.scanRange for the subnet that you want to scan

        """ This function acts as a master function for the discovery process. """

        self.activeIPList = [] # List to store active IPs based on ping
        self.newDevices = {} # Store discovered devices here
        activePortList = {} # Uses the IP address as key, contains List of ports
        activeHostnameList = {} # Uses IP address as key, contains hostname
        self.activeMACList = {} # Uses MAC as key, value is IP address
        self.foundDevices = []

        # first scan to see if the IP is active - does it respond to a ping?

        if self.discoveryLogLevel>1: self.pendingLogList.append(("Pinging hosts to determine whether they're active...",self.discoveryLog))
        
        self.discoveryPingHosts(scanRangeKey)

        sleep(10) # I hate to do this but I want to give time for threads to complete without doing something complex

        if self.discoveryLogLevel>1: self.pendingLogList.append(('Ping Sweep Complete. Active List: %s'%self.activeIPList,self.discoveryLog))

        # Acquire MAC from IP using NBTSTAT and/or ARP
            
        self.discoveryGetMACFromIP()

        # Create instances of networkDevice objects and store in self.foundDevices list

        for mac in self.activeMACList.keys():
            newDevice = networkDevice(mac)
            newDevice.setIP(self.activeMACList[mac])
            self.foundDevices.append(newDevice)
            if self.discoveryLogLevel>2: self.pendingLogList.append(('%s = %s'%(self.activeMACList[mac], mac),self.discoveryLog))

        # Perform a port scan of network devices. Update the devices in the self.newDevices list with the acquired information.
 
        self.discoveryPortScan()
        
        # attempt to get a value for the system object oid

        if self.discoveryLogLevel>1: self.pendingLogList.append(('Checking SNMP community strings...',self.discoveryLog))
        
        self.discoverySNMPTest()

        # try and get the hostname of the device

        self.getHostnameDiscovery()

        # store the inventory somewhere

        sleep(10)

        for device in self.foundDevices:
            # Store device in internal database
            self._storeDevice(device)

        # Update devices in memory
        self.readDevicesFromDatabase()

        if self.discoveryLogLevel>1: self.pendingLogList.append(('Discovery complete for %s. Found %s active devices in range.'%(scanRangeKey, len(self.foundDevices)),self.discoveryLog))

        self.exportDevices()

        self.foundDevices = []

        return 0
        
    def collectBasicSNMPInfo(self, device):

        """This function collects basic SNMP information for a device."""

        oid_values = []

        standard_oids = ['1.3.6.1.2.1.1.1.0','1.3.6.1.2.1.1.2.0','1.3.6.1.2.1.1.3.0','1.3.6.1.2.1.1.4.0','1.3.6.1.2.1.1.5.0','1.3.6.1.2.1.1.6.0','1.3.6.1.2.1.1.7.0']

        for standard_oid in standard_oids:
            pass

        #commstrings
        
        return 0
    
    def getOIDValue(self, ip, OID, communitystring):

        """The purpose of this function is to attempt to retrieve an OID from a device and return it."""

        snmpResponse = cmdgen.CommandGenerator().getCmd(
            cmdgen.CommunityData(communitystring),
            cmdgen.UdpTransportTarget((ip, self.snmpPort),timeout=self.snmpTimeOut),
            OID)[0]

        return snmpResponse

    def runDetection(self):
        pass

    def initShutdown(self):
        if self.probeoperationLogLevel > 1: self.pendingLogList.append(('Received termination signal.',self.probeoperationLog))
        self.lunarScheduler.terminate()
        self.terminateThreads = True
    
    def setScanParameters(self, scanRange, portList, communityStringsList):
        self.scanRange = scanRange
        self.portList = portList
        self.communityStringsList = communityStringsList

    def _readScanParametersFromRegistry(self):

        """ This function reads the scan parameters from the registry and stores them in memory. """
        
        # First, clean global scan configuration values
        self.scanRange = {}
        self.portList = []
        self.communityStringsList = []

        try:
            # Open key containing probe commands
            labTechKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE, self.registryConfig, 0, _winreg.KEY_ALL_ACCESS)

            # Read values in keys and assign variables to values
            DiscoveryCommunityStrings, typev = _winreg.QueryValueEx(labTechKey, "DiscoveryCommunityStrings")
            DiscoveryPorts, typev = _winreg.QueryValueEx(labTechKey, "DiscoveryPorts")
            ScanRanges, typev = _winreg.QueryValueEx(labTechKey, "ScanRanges")
            SnmpPort, typev = _winreg.QueryValueEx(labTechKey, "SnmpPort")
            self.snmpTimeOut, typev = _winreg.QueryValueEx(labTechKey, "SnmpTimeout")
            self.snmpTimeOut = int(self.snmpTimeOut)
            ThreadRatios, typev = _winreg.QueryValueEx(labTechKey, "ThreadRatios")
            self.probeoperationLogLevel, typev = _winreg.QueryValueEx(labTechKey, "OperationsLogLevel")
            self.probeoperationLogLevel = int(self.probeoperationLogLevel)
            self.discoveryLogLevel, typev = _winreg.QueryValueEx(labTechKey, "DiscoveryLogLevel")
            self.discoveryLogLevel = int(self.discoveryLogLevel)
            self.detectionLogLevel, typev = _winreg.QueryValueEx(labTechKey, "DetectionLogLevel")
            self.detectionLogLevel = int(self.detectionLogLevel)
            self.collectionLogLevel, typev = _winreg.QueryValueEx(labTechKey, "CollectionLogLevel")
            self.collectionLogLevel = int(self.collectionLogLevel)
            self.pingTimeOut, typev = _winreg.QueryValueEx(labTechKey, "PingTimeout")
            self.pingTimeOut = self.pingTimeOut * 1000
            self.portTimeOut, typev = _winreg.QueryValueEx(labTechKey, "PortTimeout")
            self.portTimeOut = float(self.portTimeOut)
            self.discoveryStartTime, typev = _winreg.QueryValueEx(labTechKey, "DiscStartTime")
            self.discoveryEndTIme, typev = _winreg.QueryValueEx(labTechKey, "DiscEndTime")
            self.discoveryCheckFrequency, typev = _winreg.QueryValueEx(labTechKey, "DiscCheckFreq")
            self.discoveryCheckFrequency = int(self.discoveryCheckFrequency)

        except WindowsError as registryerror:
            if self.probeoperationLogLevel>0:
                self.pendingLogList.append(('Error opening key while trying to access probe commands.',self.probeoperationLog))
            if self.probeoperationLogLevel>2:
                self.pendingLogList.append((str(registryerror),self.probeoperationLog))
            return 1

        # Now that the value string are read from the registry, parse them and put them in the global storage variables
        # Community Strings
        for commstring in DiscoveryCommunityStrings.split(','):
            self.communityStringsList.append(commstring)

        # Discovery Ports
        for port in DiscoveryPorts.split(','):
            self.portList.append(int(port))

        # Scan Range - dictionary with key of the starting IP and a value of the scan count 192.168.1.1 + 253 = 192.168.1.1-192.168.1.254
        for rangeString in ScanRanges.split(';'):
            if str(rangeString) <> '':
                try:
                    startPort, scanCount = rangeString.split(',')
                except ValueError as parsingError:
                    if self.probeoperationLogLevel>0: self.pendingLogList.append(("Value Error: %s"%parsingError,self.probeoperationLog))
                self.scanRange[startPort] = scanCount

        # SnmpPort

        # Type must by integer of string
        self.snmpPort = int(SnmpPort)

        # Thread Ratios
        # Define the number of threads for a given number of actions to perform
        # 1,15; would mean for every 15 items (for example IPs to scan)
        # Values for different processes are delimited by semi-colons
        # discovery;detection;collection
       
        return 0

    def discoveryGetMACFromIP(self):

        # Get the MAC address of the device - first use NBTSTAT and then use ARP Cache
        # Populate self.newDevices as MAC addresses are retrieved

        for ip in self.activeIPList:
            if self.discoveryLogLevel>1: self.pendingLogList.append(("Requesting MAC from %s using NBTSTAT"%ip,self.discoveryLog))
            self.maxDiscThreads.acquire()
            thread.start_new_thread(self.getIPMACFromNBTStat, (ip,))

        # This needs to be replaced. I basically want to use the arp cache where netstat mac is not available.

        sleep(5)
        
        arp_output = check_output(['arp','-a'], creationflags=self.CREATE_NO_WINDOW)
        macFromARPCache = self.getIPMACFromARPCache(arp_output)

        if self.discoveryLogLevel>1: self.pendingLogList.append((str(macFromARPCache),self.discoveryLog))

        try:
            del self.activeMACList['zz-zz-zz-zz']
        except KeyError:
            # No active devices found or none with unresolved macs
            pass
    
        for ip in self.activeIPList:
            if ip not in self.activeMACList.values():
                try:
                    self.activeMACList[macFromARPCache[ip]] = ip
                except KeyError:
                    self.activeIPList.remove(ip)
                    if self.discoveryLogLevel>1: self.pendingLogList.append(('Removed %s from discovery list - unable to get MAC address.'%ip,self.discoveryLog))

        # Put some kind of stop code here until all of the MAC addresses for devices are accounted for

    def getIPMACFromARPCache(self, outputOfARPCommand):
        IPMACDict = {}
        for line in outputOfARPCommand.split('\n'):
            tempList = []
            for section in line.split(' '):
                if section != '':
                    tempList.append(section)
            try:
                IPMACDict[tempList[0]] = tempList[1]
            except IndexError:
                pass
        return IPMACDict

    def getIPMACFromNBTStat(self, ipaddress):

        """This function returns the MAC address for the given IP address using nbtstat -A"""

        k32 = ctypes.windll.kernel32
        wow64 = ctypes.c_long( 0 )
        # Account for 64-bit filesystem redirection.
        k32.Wow64DisableWow64FsRedirection( ctypes.byref(wow64) )
        nbtstat_command = "nbtstat -A %s"%ipaddress
        args = shlex.split(nbtstat_command)
        proc = Popen(args, creationflags=self.CREATE_NO_WINDOW, stdout=PIPE, shell=True)
        while proc.poll() is None:
            sleep(.25)
        # MAC strings are 17 characters long.
        response = proc.communicate()[0]
        
        if "MAC" in response:
            mac = response.split('=')[1].strip()[:17]
        else:
            mac = 'zz-zz-zz-zz'

        k32.Wow64RevertWow64FsRedirection( wow64 )

        self.activeMACList[mac]=ipaddress
        
        self.maxDiscThreads.release()
        return response

    def getHostnameDiscovery(self):

        if self.discoveryLogLevel>1: self.pendingLogList.append(("Getting hostnames of devices.",self.discoveryLog))
        
        for device in self.foundDevices:
            self.maxDiscThreads.acquire()
            thread.start_new_thread(self.getHostnameFromDevice,(device,))

        if self.discoveryLogLevel>1: self.pendingLogList.append(("Hostname collection complete.",self.discoveryLog))
    
    def getHostnameFromDevice(self, device):
        try:
            device.setHostname(socket.gethostbyaddr(device.ip)[0])
        except socket.herror:
            device.setHostname(str(device.ip))
        self.maxDiscThreads.release()

        return 0

    def discoveryPingHosts(self, scanRangeKey):
        """ This function iterates through the defined scan range and creates a thread to ping"""

        if self.scanRange.has_key(scanRangeKey):
            startRange=int(str(scanRangeKey).split('.')[3])
            endRange=startRange+int(self.scanRange[scanRangeKey])
        else:
            if self.probeoperationLogLevel>0: self.pendingLogList.append(("Oops! Key not found.", self.probeoperationLog))
            raise KeyError

        scanRangeKeySplitList = scanRangeKey.split('.')

        n = startRange-1
        
        while 1:
            n=n+1
            ip = "%s.%s.%s.%s"%(scanRangeKeySplitList[0],scanRangeKeySplitList[1],scanRangeKeySplitList[2],n)
            self.maxDiscThreads.acquire()
            if self.discoveryLogLevel > 2: self.pendingLogList.append(( "Pinging %s..."%(ip), self.discoveryLog))
            thread.start_new_thread(self.pingHostEx, (ip,True))
            if n >= endRange:
                break
        if self.discoveryLogLevel > 2:
            for line in self.procSource:
                self.pendingLogList.append(( "%s - %s - %s"%(line[0], line[1], line[2]), self.discoveryLog))

    def pingHost(self, ipaddress, calledByDiscovery=False):

        """Ping the specified host and if it returns a time value, consider the host ip active."""
        
        active = False # value to be returned by function, true indicates a response
        ping_command = "ping -n 1 -l 32 -4 -w %s %s"%(self.pingTimeOut, ipaddress)
        # open a subprocess to ping the host, assign the process to variable 'proc'
        # use shlex to make sure that supplied command is properly parsed
        proc = Popen(shlex.split(ping_command), creationflags=self.CREATE_NO_WINDOW,stdout=PIPE)
        self.procSource.append((str(proc.pid),'discovery', ipaddress))
        while proc.poll() is None:
            sleep(.25)
        response = proc.communicate()[0]
        if "bytes=32 time" in response:
            active = True
            if calledByDiscovery:
                self.activeIPList.append(ipaddress)
        if calledByDiscovery:
            self.maxDiscThreads.release()
        return active

    def pingHostEx(self, ipaddress, calledByDiscovery=False):

        """Ping the specified host and if it returns a time value, consider the host ip active."""

        active = False # value to be returned by function, true indicates a response
        pingdevice = pyping.ping(ipaddress, timeout=float(1000), count=int(1)).output
        if "1 packets received" in pingdevice[3] and "("+str(socket.gethostbyname(socket.gethostname()))+")" not in str(pingdevice[1]):
            active = True
            if self.discoveryLogLevel>2: self.pendingLogList.append(( "%s - %s"%(ipaddress, pingdevice),
                                                                            self.discoveryLog))
            if calledByDiscovery:
                self.activeIPList.append(ipaddress)
        if calledByDiscovery:
            self.maxDiscThreads.release()
            
        return active

    def discoveryPortScan(self):
        """ The purpose of this function is to launch of discovery port scan of all discovered devices. """
        
        for device in self.foundDevices:
            self.maxDiscThreads.acquire()
            thread.start_new_thread(self.scanHost, (device,True))
    
    def scanHost(self, device, calledByDiscoveryThread=True):
        """"""
        
        hostPortList = []
        for currentPort in self.portList:
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(self.portTimeOut)
                s.connect((device.ip, currentPort))
                s.close()
                hostPortList.append(currentPort)
                if self.discoveryLogLevel > 1: self.pendingLogList.append(( "Successfully connected to %s on port %s"%(device.ip, currentPort),
                                                                            self.discoveryLog))
            except socket.error:
                if self.discoveryLogLevel > 1: self.pendingLogList.append(( "Failed connecting to %s on port %s"%(device.ip, currentPort),
                                                                            self.discoveryLog))
        if calledByDiscoveryThread:
            device.setPort(hostPortList)
            self.maxDiscThreads.release()
        return hostPortList

    def discoverySNMPTest(self):
        """This function will iterate through the active IPs and test the configured community strings."""
        for device in self.foundDevices:
            self.checkSNMPStringAgainstDevice(device)

    def checkSNMPStringAgainstDevice(self, instanceDevice):
        """ This function tests the specified community strings against a host and sets them on the device if they connect successfully. """
        # Pass an instance of a network device object to be modified
        for commstring in self.communityStringsList:
            self.maxDiscThreads.acquire()
            getResponse = self.snmpConnectivityCheck(instanceDevice.ip, commstring, True)
            if getResponse:
                instanceDevice.addCommString(commstring)

    def snmpConnectivityCheck(self, ip, communitystring, calledByDiscoveryThread=False):

        """This function returns true if function is able to retrieve a SNMP value
        given the parameters."""

        if self.discoveryLogLevel > 2: self.pendingLogList.append(("Attempting SNMP string \'%s\' against \'%s\'."%(communitystring, ip), self.discoveryLog))
        snmpResponse = cmdgen.CommandGenerator().getCmd(
            cmdgen.CommunityData(communitystring),
            cmdgen.UdpTransportTarget((ip, self.snmpPort),timeout=self.snmpTimeOut),
            (1,3,6,1,2,1,1,1,0))[0]
        if self.discoveryLogLevel > 2: self.pendingLogList.append(("SNMP response for string \'%s\' on \'%s\': %s"%(communitystring, ip, snmpResponse), self.discoveryLog))
        if calledByDiscoveryThread: self.maxDiscThreads.release()
        return (snmpResponse == None)

    def dumpConfig(self):
        
        """This function will write information about the lunar breeze service to a text file."""

        try:
            x=open(self.configDumpFile, 'w')
            x.write('This file was generated by Lunar Breeze. It contains configuration details. It can safely be deleted.\n')
            x.write('self.snmpTimeOut=%s\n'%self.snmpTimeOut)
            x.write('This is not a published function.')
            x.close()
        except IOError as writeError:
            if self.discoveryLogLevel > 2: self.pendingLogList.append(("Failed to write to %s. %s"%(self.configDumpFile,writeError),self.probeoperationLog))

    def _storeDevice(self, newNetworkDevice):

        """"This function stores newly found device information"""

        if self.discoveryLogLevel > 1:
            newDeviceInformation = """\n---Found by Discovery---\n%s\n%s\n%s\n%s\n%s\n---"""%(newNetworkDevice.ip, newNetworkDevice.hostname,
                                                                                    newNetworkDevice.mac, newNetworkDevice.ports, newNetworkDevice.commstrings)
            self.pendingLogList.append((newDeviceInformation,self.discoveryLog))
        pnewNetworkDevice = ''
        try:
            pnewNetworkDevice = pickle.dumps(newNetworkDevice)
        except pickle.PicklingError as pickleerror:
            if self.discoveryLogLevel > 0:
                self.pendingLogList.append(("""Error pickling device %s (%s). It will not be stored."""%(newNetworkDevice.mac,newNetworkDevice.ip),self.discoveryLog))
            if self.discoveryLogLevel > 2:
                self.pendingLogList.append(("""%s"""%pickleerror,self.discoveryLog))
            return 1
        storeDate = int((datetime.now() - datetime(1970,1,1)).total_seconds()) # current time from epoch
        
        # Insert a new entry for device or update an existing entry
        try:
            conn = sqlite3.connect(self.internalDBFile)
            c = conn.cursor()
            c.execute("""INSERT OR REPLACE INTO `networkdevices` (deviceMAC, pickledNetworkDevice, checkForOffline, lastUpdate)
                        VALUES (?, ?, ?, ?);""",
                      (newNetworkDevice.mac,pnewNetworkDevice,1,storeDate))
            conn.commit()
            conn.close()
        except sqlite3.OperationalError as sqlerror_message:
            if self.discoveryLogLevel > 0:
                self.pendingLogList.append(("""Error storing device %s (%s). It will not be stored."""%(newNetworkDevice.mac,newNetworkDevice.ip),self.discoveryLog))
            if self.discoveryLogLevel > 2:
                self.pendingLogList.append(("""%s"""%sqlerror_message,self.discoveryLog))
            return 1
        
        return 0

    def _writeLog(self, content, logfile):

        """ Function used to write message to physical log files. Should be called by _logHandler and not directly to avoid multiple threads writing at the same time. """
        
        content = strftime("%m/%d/%Y %H:%M - ", localtime()) + str(content) + "\n"
        try:
            progLog = open(logfile, "a")
            progLog.write(content)
            progLog.close()
        except IOError as writelogerror:
            # Failed to write to clean log. Attempt to write to temp folder.
            try:
                progLog = open("c:\\windows\\Temp\\lb_error_log.txt", "a")
                progLog.write(str(writelogerror))
                progLog.write(content)
                progLog.close()
            except IOError:
                # Failed to write clean log to fallback directory. Give up.
                pass

    def _monitorDevices(self):

        previousStatus = {} # dictionary containing last up/down status so updates are only done on changes

        lastCount = len(self.knownDevices) # used to gauge whether new devices have been added

        monitorList = [] # List containing instances of deviceUpMonitor objects

        currMonitor = deviceUpMonitor(logfile=self.pendingLogList, devicestatusdict=self.devicestatuses)
        thread.start_new_thread(currMonitor.monitorDevices, ())

        monitorList.append(currMonitor)

        for device in self.knownDevices:
            device_added_success = currMonitor.addManagedDevice(str(device[1]))
            if device_added_success == 1:
                # means device is at capacity and the specified ip needs to be added to a new monitor
                currMonitor = deviceUpMonitor(logfile=self.probeoperationLog, devicestatusdict=self.devicestatuses)
                monitorList.append(currMonitor)
                thread.start_new_thread(currMonitor.monitorDevices, ())
                currMonitor.addManagedDevice(str(device[1]))
                
        while self.terminateThreads != True:

            # Check for changes in devices status

            noChange = True

            for device in self.devicestatuses.keys():
                deviceS = str(device)
                try:
                    if self.devicestatuses[device] != previousStatus[deviceS]:
                        noChange=False
                        previousStatus[deviceS]=self.devicestatuses[device]
                except KeyError:
                    noChange=False
                    previousStatus[deviceS] = self.devicestatuses[device]

            if noChange == False:
                self.exportDeviceStatuses()
                # Update registry key to indicate changed status
                try:
                    if self.probeoperationLogLevel > 1: self.pendingLogList.append(("Device State Changed.",self.probeoperationLog))
                    labTechKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,self.registryStatus, 0, _winreg.KEY_ALL_ACCESS)
                    _winreg.SetValueEx(labTechKey, 'StatusChanged', 0, _winreg.REG_SZ, '1')
                except WindowsError as registryerror:
                    if self.probeoperationLogLevel > 0: self.pendingLogList.append(("Device State Changed, but could not update key.\n%s"%registryerror,self.probeoperationLog))

            # Check to see if new devices have been discovered

            for device in self.knownDevices:
                if device[1] not in self.devicestatuses.keys():
                    device_added_success = currMonitor.addManagedDevice(str(device[1]))
                    if device_added_success == 1:
                    # means device is at capacity and the specified ip needs to be added to a new monitor
                        currMonitor = deviceUpMonitor(logfile=self.probeoperationLog, devicestatusdict=self.devicestatuses)
                        monitorList.append(currMonitor)
                        thread.start_new_thread(currMonitor.monitorDevices, ())
                        currMonitor.addManagedDevice(str(device[1]))
            
            sleep(1)

    def _logHandler(self):

        """The purpose of this function is to process and write log entries logged in seperate threads in a serial manner to the appropriate logs"""

        while self.terminateThreads != True:
            if len(self.pendingLogList) < 1:
                sleep(1)
            else:
                try:
                    next_entry = self.pendingLogList.popleft()
                    content = next_entry[0]
                    logfile = next_entry[1]
                    self._writeLog(content, logfile)
                except IndexError as dequeerror:
                    self._writeLog(dequeerror, self.probeoperationLog)
        
        return 0

    def exportDevices(self):
        """" The purpose of this function is to generate a file (in JSON format) that contains the stored network device information. """

        jsonlist = []

        for device in self.knownDevices:
            
            jsonlist.append(device[2].getContents())

        try:
            sjsonlist = json.dumps(jsonlist)
        except TypeError:
            if self.discoveryLogLevel>0: self.pendingLogList.append(('Failed to serialize network device list. Did not export.',self.discoveryLog))

        if self.discoveryLogLevel>0: self.pendingLogList.append(("Exporting %s devices to 'networkdevices.json'"%len(self.knownDevices),self.discoveryLog))

        try:
            export_file = open('C:\\Windows\\LTSvc\\networkdevices.json', 'w')
            export_file.write(sjsonlist)
            export_file.close()
        except IOError as network_export_error:
            if self.discoveryLogLevel>0: self.pendingLogList.append(('Unable to write network device export file. Did not export.',self.discoveryLog))
            if self.discoveryLogLevel>2: self.pendingLogList.append(('%s'%network_export_error,self.discoveryLog))

    def exportDeviceStatuses(self):
        sjsondict = json.dumps(self.devicestatuses)

        try:
            export_file = open('C:\\Windows\\LTSvc\\devicestatus.json', 'w')
            export_file.write(sjsondict)
            export_file.close()
        except IOError as network_export_error:
            if self.discoveryLogLevel>0: self.pendingLogList.append(('Unable to write network device status export file. Did not export.',self.discoveryLog))
            if self.discoveryLogLevel>2: self.pendingLogList.append(('%s'%network_export_error,self.discoveryLog))

    def readDevicesFromDatabase(self):
        """ The purpose of this function is to read devices from the internal database and populate an internal instance of them using the networkDevice class. """

        if self.probeoperationLogLevel > 1: self.pendingLogList.append(("Loading known network devices from internal database file...",self.probeoperationLog))

        self.knownDevices = []

        # For each device in the internal database, load that device into a tuple for the probe monitor engine

        read_device_query = """SELECT * from `networkdevices`;"""
        deviceCount = 0

        try:
            conn = sqlite3.connect(self.internalDBFile)
            c = conn.cursor()
            for storeddevice in c.execute(read_device_query):
                newDevice = None
                try:
                    newDevice = pickle.loads(str(storeddevice[1]))
                except pickle.UnpicklingError as unpickleerror:
                    if self.probeoperationLogLevel > 0: self.pendingLogList.append(("Error unpickling device from database.",self.probeoperationLog))
                    if self.probeoperationLogLevel > 2: self.pendingLogList.append(("%s"%unpickleerror,self.probeoperationLog))
                except AttributeError as unpickleerror:
                    if self.probeoperationLogLevel > 0: self.pendingLogList.append(("Error unpickling device from database.",self.probeoperationLog))
                    if self.probeoperationLogLevel > 2: self.pendingLogList.append(("%s"%unpickleerror,self.probeoperationLog))
                if newDevice == None:
                    pass
                else:
                    deviceCount = deviceCount+1
                    self.knownDevices.append((storeddevice[0], newDevice.ip , newDevice, storeddevice[2])) 
        except sqlite3.OperationalError as sqlerror_message:
            if self.probeoperationLogLevel > 0: self.pendingLogList.append(("Database error encountered when reading stored network devices.",self.probeoperationLog))
            if self.probeoperationLogLevel > 2: self.pendingLogList.append(("%s"%sqlerror_message,self.probeoperationLog))

        # For informational level logging add the number of devices read

        if self.probeoperationLogLevel > 1: self.pendingLogList.append(("Loaded %s device(s) from the Lunar Breeze's internal database."%deviceCount,self.probeoperationLog))

        return 0

    def _preStartupCheck(self):

        """ This function is intended to be called by the constructor to make sure the appropriate registry keys/files exist. If not, attempt to make them. """

        # Check for internal database file containing network devices
        conn = sqlite3.connect(self.internalDBFile)
        c = conn.cursor()
        try:
            c.execute("""CREATE TABLE IF NOT EXISTS `networkdevices` (deviceMAC text PRIMARY KEY, pickledNetworkDevice text, checkForOffline int, lastUpdate int);""")
            conn.commit()
            c.execute('SELECT * from `networkdevices`;')
        except sqlite3.OperationalError as sqlerror_message:
            if self.probeoperationLogLevel > 2:
                self.pendingLogList.append(("""%s"""%sqlerror_message,self.probeoperationLog))
            if self.probeoperationLogLevel > 1:
                self.pendingLogList.append(("Failed to create `networkdevices` table.",self.probeoperationLog))

        # Check for core registry keys
        for key in [self.registryBase,
                     self.registryStatus,
                     self.registryConfig,
                     self.registryCommands]:
            try:
                labTechKey = _winreg.CreateKey(_winreg.HKEY_LOCAL_MACHINE,key)
            except WindowsError as reg_createerror:
                if self.probeoperationLogLevel > 0: self.pendingLogList.append(("Failed to create key: %s"%(str(labTechKey)),self.probeoperationLog))
                if self.probeoperationLogLevel > 1: self.pendingLogList.append((str(strreg_createrror),self.probeoperationLog))
                                                                               
        # Check for command registry keys

        for commandregistrykeys in [('Commands','PerformDiscovery','0'),
        ('Commands','ReloadConfig','0'),
        ('Commands','RestartProbe','0')]:
            self._checkAndReplaceRegistryKey(commandregistrykeys)
        
        # Check for config registry keys

        localip = socket.gethostbyname(socket.gethostname()).split('.')
        class_c_config = "%s.%s.%s.1,253"%(localip[0],localip[1],localip[2])

        for configregistrykeys in [('Config','DefaultOfflineCheck','1'),
        ('Config','DiscoveryCommunityStrings','public,'),
        ('Config','DiscoveryPorts','21,23,80,139'),
        ('Config','ScanRanges',''),
        ('Config','SnmpPort','161'),
        ('Config','ThreadRatios','1,30'),
        ('Config', 'OperationsLogLevel','1'),
        ('Config', 'DiscoveryLogLevel','1'),
        ('Config', 'DetectionLogLevel','1'),
        ('Config', 'CollectionLogLevel','1'),
        ('Config', 'PingTimeOut', '1'),
        ('Config', 'PortTimeOut', '.5'),
        ('Config', 'ScanRanges', class_c_config),
        ('Config', 'DiscStartTime','00:00'),
        ('Config', 'DiscEndTime', '23:59'),
        ('Config', 'DiscCheckFreq', '60'),
        ('Config', 'SnmpTimeout', '1')]:
            self._checkAndReplaceRegistryKey(configregistrykeys)
                
        # Check for status registry keys

        for configregistrykeys in [('Status','ConfigChanged','0'),
        ('Status','StatusChanged','0'),
        ('Status','InventoryUpdated','0')]:
            self._checkAndReplaceRegistryKey(configregistrykeys)
        
        return 0
    
    def _checkAndReplaceRegistryKey(self, keyPathAndValue):
        """ The purpose of this internal function is to accept a registry key and value, check for that key's existence and if it doesn't
        exist, create it with the specified value."""

        try:
            labTechKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,self.registryBase+"\\"+keyPathAndValue[0], 0, _winreg.KEY_ALL_ACCESS)
            RequiredKey, typev = _winreg.QueryValueEx(labTechKey, keyPathAndValue[1])
        except WindowsError:
            # create key with default value
            if self.probeoperationLogLevel > 0: self.pendingLogList.append(("Creating missing key: %s"%(keyPathAndValue[0]+keyPathAndValue[1]),self.probeoperationLog))
            try:
                labTechKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,self.registryBase+"\\"+keyPathAndValue[0], 0, _winreg.KEY_ALL_ACCESS)
                _winreg.SetValueEx(labTechKey, keyPathAndValue[1], 0, _winreg.REG_SZ, keyPathAndValue[2])
            except WindowsError:
                if self.probeoperationLogLevel > 0: self.pendingLogList.append(("Failed to create key: %s"%(keyPathAndValue[0]+keyPathAndValue[1]),self.probeoperationLog))

    def _commandHandler(self, checkFrequency=5):

        """This thread periodically polls the machine registry to see if there are pending commands from LabTech."""

        runDiscovery = 0
        restartProbe = 0
        reloadConfig = 0
        labTechKey = None
        
        while self.terminateThreads != True:
            try:
                # Open key containing probe commands
                labTechKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,self.registryCommands, 0, _winreg.KEY_ALL_ACCESS)

                # Check for discovery request

                runDiscovery, typev = _winreg.QueryValueEx(labTechKey, "PerformDiscovery")
                restartProbe, typev = _winreg.QueryValueEx(labTechKey, "RestartProbe")
                reloadConfig, typev = _winreg.QueryValueEx(labTechKey, "ReloadConfig")

            except WindowsError as registryerror:
                if self.probeoperationLogLevel>0: self.pendingLogList.append(('Error opening key while trying to access probe commands.', self.probeoperationLog))
                if self.probeoperationLogLevel>2: self.pendingLogList.append((str(registryerror), self.probeoperationLog))

            if runDiscovery == '1':
                try:
                    _winreg.SetValueEx(labTechKey, 'PerformDiscovery', 0, _winreg.REG_SZ, '0')
                except WindowsError as registryerror:
                    if self.probeoperationLogLevel>0: self.pendingLogList.append(("Error updating 'PerformDiscovery' key.", self.probeoperationLog))
                    if self.probeoperationLogLevel>2: self.pendingLogList.append((str(registryerror), self.probeoperationLog))
                runDiscovery = 0

                # If discovery is already in progress, don't launch another discovery thread.
                if self.discoveryInProgress == False:
                    thread.start_new_thread(self.runDiscovery, ())
                else:
                    if self.probeoperationLogLevel>0: self.pendingLogList.append(("Discovery already in progress. Registry key reset.", self.probeoperationLog))
            if restartProbe == '1':
                # This will restart the Lunar Breeze service... or just shut it down.
                _winreg.SetValueEx(labTechKey, 'RestartProbe', 0, _winreg.REG_SZ, '0')
                if self.probeoperationLogLevel>0: self.pendingLogList.append(("Restarting the Lunar Breeze service.", self.probeoperationLog))
                if self.probeoperationLogLevel>2: self.pendingLogList.append(("Hopefully the service starts again.", self.probeoperationLog))
                self.restartMe = True
            if reloadConfig == '1':
                # This is intended to by run when one wants the probe to recheck the configuration settings set in the probe's registry
                try:
                    _winreg.SetValueEx(labTechKey, 'ReloadConfig', 0, _winreg.REG_SZ, '0')
                    if self.probeoperationLogLevel>1: self.pendingLogList.append(("Reloading parameters from registry.",self.probeoperationLog))
                except WindowsError as registryerror:
                    if self.probeoperationLogLevel>0:
                        self.pendingLogList.append(("Unable to reset 'ReloadConfig' registry value.",self.probeoperationLog))
                    if self.probeoperationLogLevel>2:
                        self.pendingLogList.append((str(registryerror),self.probeoperationLog))
                self._readScanParametersFromRegistry()

            try:
                _winreg.CloseKey(labTechKey)
            except:
                pass

            ##  Wait for the specified amount of time to pass before checking for registry commands ##
            sleep(checkFrequency)


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


class lunarScheduler:

    """ This class is designed to be run as a background thread and handle kickoff of discovery scans. """
    
    def __init__(self, startTime='00:00', endTime='23:59', runFrequency=60):
        self.possibleTimes = []
        self.spanDay = False
        self.logHandler = None
        self.runFrequency = timedelta(minutes=runFrequency)
        self.startTime = startTime
        self.endTime = endTime
        self.terminateThread = False

        # Remove complete key references later
        self.registryBase = """Software\\LunarBreeze"""
        self.registryConfig = self.registryBase + """\\Config"""
        self.registryStatus = self.registryBase + """\\Status"""
        self.registryCommands = self.registryBase + """\\Commands"""

        self.calculateRuntimes()
        thread.start_new_thread(self._checkRunTime,())
        
    def setLogFile(self, logHandler):
        self.logHandler=logHandler

    def terminate(self):
        self.terminateThread = True
    
    def calculateRuntimes(self):

        """Calculate all of the possible runtimes for discovery scans."""

        runTimes = []

        has_spanned=False

        startTimeObject = datetime.strptime(self.startTime, '%H:%M')
        endTimeObject = datetime.strptime(self.endTime, '%H:%M')
        nextStartTime =  startTimeObject

        if startTimeObject > endTimeObject:
            spanDay=True

        while 1:
            # Evaluate the exit conditions and exit or add another runtime and increment nextStartTime.

            scanTimeToAdd = nextStartTime + self.runFrequency
            
            if self.spanDay==True:
                if (scanTimeToAdd.timetz() > endTimeObject.timetz()) and (scanTimeToAdd.day <> endTimeObject.day):
                    break
            else:
                if nextStartTime + self.runFrequency > endTimeObject:
                    break

            runTimes.append(scanTimeToAdd.strftime('%H:%M'))
            nextStartTime = scanTimeToAdd

        self.possibleTimes = runTimes

        return runTimes
            
    def _checkRunTime(self):

        # Every 10 seconds check whether a scheduled discovery should take place.

        while self.terminateThread!=True:
            sleep(10)
            if strftime('%H:%M') in self.possibleTimes:
                try:
                    x = open("""C:\\Windows\\Temp\\lb_scheduler_log.txt""",'a')
                    x.write("Match found! %s is contained in time list.\n"%strftime('%H:%M'))
                    x.close()
                    labTechKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,self.registryCommands, 0, _winreg.KEY_ALL_ACCESS)
                    _winreg.SetValueEx(labTechKey, 'PerformDiscovery', 0, _winreg.REG_SZ, '1')
                except WindowsError as registryerror:
                    x = open("""C:\\Windows\\Temp\\lb_scheduler_log.txt""",'a')
                    x.write("Failed to write registry key!\n")
                    x.write("%s\n"%registryerror)
                    x.close()
                    #if self.probeoperationLogLevel>0: self.pendingLogList.append(("Scheduled discovery event was found but the service was unable to initiate a scan.", self.probeoperationLog))
                sleep(60)
        return 0

class deviceUpMonitor:

    """ This class is used to monitor network devices through ICMP requests. """
    
    def __init__(self, testInterval=30, pingTimeout=1000, logfile='', devicestatusdict={}):
        
        self.testInterval=testInterval
        self.pingTimeOut=pingTimeout
        self.terminateThread = False
        # self.managedIPs will be a dictionary with the IP as key and the value, a tuple representing # (onlinestatus,)
        self.managedIPs = {}
        self.offlineDevices = []
        self.pendingLogFile=logfile
        self.atCapacity = False
        self.deviceStatusDict = devicestatusdict
        self.timeDelay = int(self.testInterval*.25)
        self.maxDevices = int((self.testInterval / (self.pingTimeOut/1000))*.75)
        self.monitordevicecount = 0
                
    def addManagedDevice(self, ip):

        if len(self.managedIPs)>=self.maxDevices:
            return 1
        else:
            self.managedIPs[ip] = -1
            self.timeDelay = int(self.maxDevices-self.getDeviceCount())+int(self.testInterval*.25)
            return 0
    
    def getDeviceCount(self):
        """ This function returns the number of devices this monitor is currently watching. """
        return len(self.managedIPs)

    def pingHost(self, ipaddress):

        """Ping the specified host and if it returns a time value, consider the host ip active."""
        
        active = False # value to be returned by function, true indicates a response
        ping_command = "ping -n 1 -l 32 -4 -w %s %s"%(self.pingTimeOut, ipaddress)
        # open a subprocess to ping the host, assign the process to variable 'proc'
        # use shlex to make sure that supplied command is properly parsed
        proc = Popen(shlex.split(ping_command), creationflags=0x08000000,stdout=PIPE)
        while proc.poll() is None:
            sleep(.25)
        response = proc.communicate()[0]
        if "bytes=32 time" in response:
            active = True
            self.managedIPs[ipaddress]=1
        else:
            self.managedIPs[ipaddress]=0
        return active

    def pingHostEx(self, ipaddress):

        """Ping the specified host and if it returns a time value, consider the host ip active."""

        active = False # value to be returned by function, true indicates a response
        pingdevice = pyping.ping(ipaddress, timeout=float(self.pingTimeOut), count=int(1)).output
        if "1 packets received" in pingdevice[3] and "("+str(socket.gethostbyname(socket.gethostname()))+")" not in str(pingdevice[1]):
            active = True
            self.managedIPs[ipaddress]=1
        else:
            self.managedIPs[ipaddress]=0
        return active

    def terminate(self):
        """ Calling this function tells the monitor thread to die. """
        self.terminateThread = True
        return 0

    def exportDevices(self):
        """ This function updates a global dictionary of IP statuses."""

        for device in self.managedIPs.keys():
            self.deviceStatusDict[device] = self.managedIPs[device]

    def monitorDevices(self):
        """ This function starts monitoring self.managedIP list"""

        while self.terminateThread == False:

            offlinecount = 0
            self.monitordevicecount = 0
            
            for ip in self.managedIPs.keys():
                self.pingHostEx(str(ip))
                self.monitordevicecount = self.monitordevicecount + 1

            self.exportDevices()
                                      
            sleep(self.timeDelay)
           
        return 0
    

class lbThreadManager:
    """A class for the monitoring of threads spawned in a program to allow for an advanced debugging platform."""
    
    def __init__(self):
        # List containing thread information
        self.threadList = []
    def startThread(self, newThread, description):
        self.threadList.append((newThread.get_ident(), description))
    def stopThread(self):
        pass
    def getThreadList(self):
        return self.threadList
    def _removeThreadFromList(self, threadID):
        pass

class lunarBreezeService(win32serviceutil.ServiceFramework):

    _svc_name_ = 'LunarBreeze'
    _svc_display_name_ = 'Lunar Breeze'
    _svc_description_ = "A simple network discovery and monitoring tool."
    
    def __init__(self, args):
        self.runservice=1
        win32serviceutil.ServiceFramework.__init__(self, args)
        
    def SvcDoRun(self):
        #servicemanager.LogInfoMsg("LunarBreeze - Starting service.")
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
               0xA, ("Lunar Breeze is starting.",))
        self.theProbe=lunarBreezeProbe()
        while self.runservice:
            sleep(1)
            if self.theProbe.restartMe == True:
                win32serviceutil.RestartService('LunarBreeze')
            
    def SvcStop(self):
        #servicemanager.LogInfoMsg("LunarBreeze - Recieved stop signal")
        servicemanager.LogMsg(servicemanager.EVENTLOG_INFORMATION_TYPE,
               0xB, ("Lunar Breeze is shutting down.",))
        self.theProbe.initShutdown()
        self.runservice=0
        self.ReportServiceStatus(win32service.SERVICE_STOP_PENDING)

if __name__ == "__main__":
    win32serviceutil.HandleCommandLine(lunarBreezeService)
