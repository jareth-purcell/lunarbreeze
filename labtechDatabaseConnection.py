import _winreg
import MySQLdb
from os import path
import ConfigParser as configparser
from time import strftime, localtime

class labTechDatabaseConnection:

    """"Class for connecting and interacting with the LabTech database. Written by Jareth Purcell <jareth.purcell@gmail.com>."""
    
    def __init__(self, configFileName='labtechsql.ini'):

        self.config_file_name = configFileName
        
        # Variables used to connect to LabTech database.
        self.host = '127.0.0.1'
        self.user = 'root'
        self.sqlPassword = ''
        self.db = 'labtech'
        self.cursor = None
        self.debug = False
        self.getCredentialsFromRegistry()
        self.getCredentialsFromFile()
        if self.hasConnectionInformation():
            self.connect()
        else:
            self.writeToLog("Insufficient Information to Connect.")
            
    def close(self):
    # labTechDatabaseConnection.close commits changes to the SQL database and then closes the connection.
        try:
            self.conn.commit()
            self.conn.close()
            return 0
        except MySQLdb.Error:
            return 1
        except AttributeError:
            return 1
        
    def connect(self):
        try:
            self.conn = MySQLdb.connect (host = self.host,
                           user = self.user,
                           passwd = self.sqlPassword,
                           db = self.db)
            self.cursor = self.conn.cursor()
            return 0
        except MySQLdb.Error:
            self.writeToLog("""Failed to connect to LabTech database.""")
            return 1
    
    def execute(self, sqlStatement):
        if self.cursor != None:
            self.cursor.execute(sqlStatement)
            self.conn.commit()
            return self.cursor.fetchall()
        else:
            self.writeToLog("""Exception: No active database connection.""")
            return 1


    def getCredentialsFromFile(self):
    # This function parses the connection information out of the file defined in the variable self.config_file_name.
    # I created a few different return codes in case I want to have more specific error handling / logging in the future.
    #
    # Return Codes
    # 0 - Successfully Read Information
    # 1 - Configuration File Not Found
    # 2 - Configuration File Missing '[connectionSettings]' Section
    # 3 - General Parsing Error

        """ This function attempts to retrieve connection settings from the specified configuration file."""

        # Check for configuration file in the filesystem. If it doesn't exist, return error code 1
        if not path.isfile(self.config_file_name):
            if self.debug: print "ERROR: Could not find '%s'"%self.config_file_name
            self.writeToLog("ERROR: Could not find connection configuration file: '%s'."%self.config_file_name)
            return 1

        # Initialize Config Parser
        config = configparser.SafeConfigParser(allow_no_value=False)
        try:
            config.read(self.config_file_name)
        except configparser.MissingSectionHeaderError:
            return 2
        except configparser.ParsingError:
            if self.debug: print "ERROR: General error parsing '%s'."%self.config_file_name
            self.writeToLog("ERROR: General error parsing '%s'."%self.config_file_name)
            return 3

        # Check the configuration file for the bare minimum settings.

        if not config.has_section('connectionSettings'):
            if self.debug: print "ERROR: Configuration file '%s' must contain 'connectionSettings' section."%self.config_file_name
            self.writeToLog("ERROR: Configuration file '%s' must contain 'connectionSettings' section."%self.config_file_name)
            return 2

        if not config.has_option('connectionSettings','serveraddr'):
            if self.debug: print "WARNING: Configuration file '%s' does not contain 'serveraddr' option in 'connectionSettings' section"%self.config_file_name
            self.writeToLog("WARNING: Configuration file '%s' does not contain 'serveraddr' option in 'connectionSettings' section"%self.config_file_name)

        # Hidden options
        if config.has_option('connectionSettings','Author'): self.writeToLog("Written by Jareth Purcell <jareth.purcell@gmail.com>")
        if config.has_option('connectionSettings','LabTechBug'): self.writeToLog("The core is solid!")

        # If the value exists in the configuration file then assign it to the variable.
        if config.has_option('connectionSettings','serveraddr'): self.host=config.get('connectionSettings','serveraddr')
        if config.has_option('connectionSettings','username'): self.user=config.get('connectionSettings','username')
        if config.has_option('connectionSettings','password'): self.sqlPassword=config.get('connectionSettings','password')
        if config.has_option('connectionSettings','database'): self.db=config.get('connectionSettings','database')
        
        return 0

    def legacyGetCredentialsFromFile(self):
        checkForPassword = False
        tempPassword = None
        try:
            configFile=open('labtechsql.config', 'r')
            for line in configFile:
                splitline=line.split('=')
                if splitline[0]=='hostname':
                    if len(splitline[1]) > 0:
                        self.host = splitline[1].strip()
                elif splitline[0]=='username':
                    if len(splitline[1]) > 0:
                        self.user=splitline[1].strip()
                elif splitline[0]=='password':
                    if len(splitline[1]) > 0:
                        self.sqlPassword = splitline[1].strip()
                elif splitline[0]=='database':
                    if len(splitline[1]) > 0:
                        self.db = splitline[1].strip()
                elif splitline[0]=='author':
                    self.writeToLog("About the Author","This program was written by Jareth Purcell <jareth.purcell@gmail.com>.")
            configFile.close()
            return 0
        except IOError:
            return 1
        
    def getCredentialsFromRegistry(self):
        # Retrieve SQL password for registry

        """ This function attempts to retrieve the LabTech database mySQL root password from the registry."""
        
        try:
            labTechKey = _winreg.OpenKey(_winreg.HKEY_LOCAL_MACHINE,"Software\\Wow6432Node\\LabTech\\Setup")
            self.sqlPassword, typev = _winreg.QueryValueEx(labTechKey, "RootPassword")
            return 0
        except WindowsError:
            if self.debug: self.writeToLog("Failed to retrieve LabTech database password from registry key HKLM\\Software\\Wow6432Node\\LabTech\\Setup\\RootPassword")
            return 1
        
    def hasConnectionInformation(self):
        hasInfo = True
        if self.host == '': hasInfo=False
        if self.sqlPassword == '': hasInfo=False
        return hasInfo

    def writeToLog(self, message):
    # Function intended to use for logging results / errors for the labtech database class
    # Don't prefix messages with \n's or it will mess up timestamp formatting.
    # Messages are automatically appended with a \n
        message = strftime("%m/%d/%Y %H:%M - ", localtime()) + str(message) + "\n"
        try:
            connectionLog = open("connection_errorlog.txt", "a")
            connectionLog.write(message)
            connectionLog.close()
        except IOError:
            # Failed to write to connection log. Attempt to write to temp folder.
            try:
                connectionLog = open("c:\\windows\\Temp\\connection_errorlog.txt", "a")
                connectionLog.write(message)
                connectionLog.close()
            except IOError:
                # Failed to write connection log to fallback directory. Give up.
                if self.debug: print 'Failed to log message. Giving up.'
    
