from distutils.core import setup
import sys

options = {}

if "py2exe" in sys.argv:
  import py2exe
  # fix executables
  options['service'] = [{'modules':'lunarbreeze',
                         'cmdline_style':'pywin32',
                         "icon_resources":[(0,"lunarbreeze.ico")]}]
  # EXE descriptions
  options['name']='Lunar Breeze'
  options['version']='1.0.1'
  options['description']='Lunar Breeze Service'
  options['author']='Jareth Purcell'
  # Build options
  options['zipfile'] = None
  #options['excludes'] = '_ssl'
  
  # add files not found my modulefinder
  options['options'] = {
    'py2exe': {
      'includes': [
        'pysnmp.smi.mibs.*',
        'pysnmp.smi.mibs.instances.*',
        'win32com',
        'win32service',
        'win32serviceutil',
        'win32event'
      ],
      'bundle_files': 1
    }
  }

setup(**options)
