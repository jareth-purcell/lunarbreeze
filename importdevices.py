import json
import labtechDatabaseConnection
import sys
import argparse # to create helpful message about usage

# Usage: importdevices [pathtofile] [mode] [computerid]

# Mode 1 = device inventory
# Mode 2 = device status

def importNetworkDevices(pathToFile, mode, computerid, use_coretables=False):
    try:
        jsonfile=open(pathToFile,'r')
    except IOError:
        print "Fatal Error! Could not open '%s' for reading. Exiting program."%pathToFile
        sys.exit(1)
    jsonfile_contents=jsonfile.read()
    json_instance=json.loads(jsonfile_contents)
    ltc = labtechDatabaseConnection.labTechDatabaseConnection()
    if mode == 1:
        for device in json_instance:
            snmp_enabled='0'
            if device['commstrings'] != '[]':
                snmp_enabled='1'
            # define each column value with any sanitation/formatting to make sql statement declaration more readable
            locationid = 0
            hostname = str(device['hostname'])
            ip = str(device['ip'])
            mac = str(device['mac'])
            ports = (str(device['ports']).replace('[','')).replace(']','')
            commstrings = ''
            if use_coretables:
                # If using the coretables, get the `locationid` of `computerid`
                deviceid=ltc.execute("""SELECT IFNULL(`DeviceID`,0) from `networkdevices` WHERE `mac` LIKE "%%%s%%";"""%mac
                if deviceid=0:
                    sqlstatement="""INSERT INTO `networkdevices` (DeviceID, LocationID, IPAddress, Name, SNMP, SNMPComm,) VALUES ("%s", "%s", "%s", "%s", "%s", "%s")
                        ON DUPLICATE KEY UPDATE , ;"""%()
                else:
                    # adjust column names to networkdevices table contents
                    sqlstatement="""UPDATE `networkdevices` SET deviceComputerID="%s", deviceHostname="%s", deviceIPAddress="%s",
                            deviceOpenPorts="%s", deviceSNMPEnabled="%s",deviceSNMPCommStrings="%s" WHERE deviceid=%s;"""%(computerid, str(device['hostname']), str(device['ip']),
                                                                                                         str(device['ports']),snmp_enabled,str(device['commstrings']),deviceid)
            else:
                sqlstatement="""INSERT INTO `plugin_lunarbreeze_devices` (deviceComputerID, deviceHostname, deviceMACAddress, deviceIPAddress, deviceOpenPorts, deviceSNMPEnabled,
                            deviceSNMPCommStrings) VALUES ("%s","%s","%s","%s","%s","%s","%s")
                            ON DUPLICATE KEY UPDATE deviceComputerID="%s", deviceHostname="%s", deviceIPAddress="%s", deviceOpenPorts="%s", deviceSNMPEnabled="%s",deviceSNMPCommStrings="%s";"""%(
                                computerid,str(device['hostname']),str(device['mac']),str(device['ip']),(str(device['ports']).replace('[','')).replace(']',''),
                                snmp_enabled,str(device['commstrings']), computerid, str(device['hostname']), str(device['ip']),str(device['ports']),snmp_enabled,str(device['commstrings']))
            ltc.execute(sqlstatement)
        ltc.close()
    elif mode == 2:
        for device in json_instance:
            ip = str(device)
            status = json_instance[pythonip]
            sqlstatement="""UPDATE `plugin_lunarbreeze_devices` SET deviceOnline="%s" WHERE deviceIPAddress="%s" AND deviceComputerID="%s";"""%(status,ip,computerid)
            ltc.execute(sqlstatement)
        ltc.close()
    else:
        print 'Unknown mode specified. Mode option should be 1 or 2.'

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="A program to import network device information from JSON files exported by Lunar Breeze to the LabTech Database.",
        epilog="Lunar Breeze was designed and written by Jareth Purcell."
        )
    parser.add_argument('filename', help="The JSON file from the remote Lunar Breeze service with stored device information.")
    parser.add_argument('mode', help="Indicates the type of information that the JSON file contains (1 - network inventory, 2 - device status).", choices=[1,2], type=int)
    parser.add_argument('computerid', help="The computer where the remote Lunar Breeze service resides so it can be associated with an agent in LabTech.",type=int)
    parser.add_argument('--coretables', help="Information will be stored in native LabTech tables.",action="store_true")
    args = parser.parse_args()
    pathtofile = args.filename
    mode = args.mode
    computerid = args.computerid
    importNetworkDevices(pathtofile, mode, computerid, args.coretables)
