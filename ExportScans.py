### Need a file named config.ini that contains API access and secret key information encoded in base64.

# Native Python libraries
import json
import base64
import os
import time

# Install using pip
import requests
import configparser


# Set API access information from config.ini, stored in the directory the app is launched from
config = configparser.ConfigParser()
config.read(f'.\config.ini')
apiaccesskey = config['Tenable']['apiaccesskey']
apisecretkey = config['Tenable']['apisecretkey']

# Put the name of the scan in the string below, then save and run the script.  
scan_name_for_exports = ''


### Create folder for exported files to go into
def createExportFolder(scan_name):
    if not os.path.exists("./Scans"):
        os.mkdir("./Scans")
    if not os.path.exists(f"./Scans/{scan_name}"):
        os.mkdir(f"./Scans/{scan_name}")


### Gets the schedule_uuid to identify specific scans for exporting.  Using this method grabs the latest scan results.
def GetScanIdByName(scan_name):
    url = "https://cloud.tenable.com/scans"
    headers = {'X-ApiKeys': f'accessKey={apiaccesskey}; secretKey={apisecretkey};', 'accept': 'application/json'}
    sendinfo = requests.request("GET", url, headers=headers)
    response = sendinfo.json()
    for scan in response['scans']:
        if scan_name == scan['name']:
            scan_id = scan['schedule_uuid']
            return scan_id
        
        

# Make call to Tenable, export Exec Summary PDF and download.
def ExportExecutiveSummaryPdfReport(scan_name):
    schedule_uuid = GetScanIdByName(scan_name)
    url = f"https://cloud.tenable.com/scans/{schedule_uuid}/export"
    payload = json.dumps({'format':'pdf',
                          'chapters': 'vuln_hosts_summary'
                          })
    headers = {
        'X-ApiKeys' : f'accessKey={apiaccesskey}; secretKey={apisecretkey}',
        'accept': "application/json",
        'content-type': "application/json"
        }
    sendinfo = requests.request("POST", url, data=payload, headers=headers)
    response = sendinfo.json()
    ExecutiveSummaryFileId = response['file']
    return response['file']
        

### By Asset Report
def ExportByAssetPdfReport(scan_name):
    schedule_uuid = GetScanIdByName(scan_name)
    url = f"https://cloud.tenable.com/scans/{schedule_uuid}/export"
    payload = json.dumps({'format':'pdf',
                          'chapters': 'vuln_by_host'
                          })
    headers = {
        'X-ApiKeys' : f'accessKey={apiaccesskey}; secretKey={apisecretkey}',
        'accept': "application/json",
        'content-type': "application/json"
        }
    sendinfo = requests.request("POST", url, data=payload, headers=headers)
    response = sendinfo.json()
    ByAssetFileId = response['file']
    return response['file']    


### By Vulnerability Report
def ExportByPluginPdfReport(scan_name):
    schedule_uuid = GetScanIdByName(scan_name)
    url = f"https://cloud.tenable.com/scans/{schedule_uuid}/export"
    payload = json.dumps({'format':'pdf',
                          'chapters': 'vuln_by_plugin'
                          })
    headers = {
        'X-ApiKeys' : f'accessKey={apiaccesskey}; secretKey={apisecretkey}',
        'accept': "application/json",
        'content-type': "application/json"
        }
    sendinfo = requests.request("POST", url, data=payload, headers=headers)
    response = sendinfo.json()
    ByPluginFileId = response['file']
    return response['file']


### CSV Report
def ExportCsvReport(scan_name):
    schedule_uuid = GetScanIdByName(scan_name)
    url = f"https://cloud.tenable.com/scans/{schedule_uuid}/export"
    payload = json.dumps({'format':'csv'})
    headers = {
        'X-ApiKeys' : f'accessKey={apiaccesskey}; secretKey={apisecretkey}',
        'accept': "application/json",
        'content-type': "application/json"
        }
    sendinfo = requests.request("POST", url, data=payload, headers=headers)
    response = sendinfo.json()
    CsvFileId = response['file']
    return response['file']


### Checks status of requested export 
def CheckExportStatus(scan_name, file_id):
    scheduleUuid = GetScanIdByName(scan_name)
    url = f"https://cloud.tenable.com/scans/{scheduleUuid}/export/{file_id}/status"
    headers = {
        'X-ApiKeys' : f'accessKey={apiaccesskey}; secretKey={apisecretkey};',
        'accept': "application/json",
        'content-type': "application/json"
        }
    sendinfo = requests.request("GET", url, headers=headers)
    response = sendinfo.json()
    return response['status']



### Downloads the Executive Summary report
def GetExecutiveSummaryPdfExport(scan_name):
    createExportFolder(scan_name)
    ExecutiveSummaryFileID = ExportExecutiveSummaryPdfReport(scan_name)
    scheduleUuid = GetScanIdByName(scan_name)
        
    while True:
        url = f"https://cloud.tenable.com/scans/{scheduleUuid}/export/{ExecutiveSummaryFileID}/download"
        headers = {
            'X-ApiKeys' : f'accessKey={apiaccesskey}; secretKey={apisecretkey}',
            'accept': "application/octet-stream",
            }
        CurrentExportStatus = CheckExportStatus(scan_name, ExecutiveSummaryFileID)
        if CurrentExportStatus == 'ready':
            sendInfo = requests.request("GET", url, headers=headers)
            print("Downloading Executive Summary Report...")
            newPdfReport = open(f"./Scans/{scan_name}/ExecutiveSummary.pdf", "w+b")
            newPdfReport.write(sendInfo.content)
            newPdfReport.close()
            break
        else:
            time.sleep(5)
  

### Downloads the By Asset Export
def GetByAssetPdfExport(scan_name):
    createExportFolder(scan_name)
    ByAssetFileID = ExportByAssetPdfReport(scan_name)
    scheduleUuid = GetScanIdByName(scan_name)

    while True:
        url = f"https://cloud.tenable.com/scans/{scheduleUuid}/export/{ByAssetFileID}/download"
        headers = {
            'X-ApiKeys' : f'accessKey={apiaccesskey}; secretKey={apisecretkey}',
            'accept': "application/octet-stream",
            }
        CurrentExportStatus = CheckExportStatus(scan_name, ByAssetFileID)
        if CurrentExportStatus == 'ready':
            sendInfo = requests.request("GET", url, headers=headers)
            print("Downloading By Asset report...")
            newPdfReport = open(f"./Scans/{scan_name}/By Asset Report.pdf", "w+b")
            newPdfReport.write(sendInfo.content)
            newPdfReport.close()
            break
        else:
            time.sleep(5)


### Downloads the By Plugin Export
def GetByPluginPdfExport(scan_name):
    createExportFolder(scan_name)
    ByPluginFileId = ExportByPluginPdfReport(scan_name)
    scheduleUuid = GetScanIdByName(scan_name)
    while True:
        url = f"https://cloud.tenable.com/scans/{scheduleUuid}/export/{ByPluginFileId}/download"
        headers = {
            'X-ApiKeys' : f'accessKey={apiaccesskey}; secretKey={apisecretkey}',
            'accept': "application/octet-stream",
            }
        CurrentExportStatus = CheckExportStatus(scan_name, ByPluginFileId)
        if CurrentExportStatus == 'ready':
            sendInfo = requests.request("GET", url, headers=headers)
            print("Downloading By Vulnerability report...")
            newPdfReport = open(f"./Scans/{scan_name}/By Vulnerability Report.pdf", "w+b")
            newPdfReport.write(sendInfo.content)
            newPdfReport.close()
            break
        else:
            time.sleep(5)


### CSV Export
def GetCsvExport(scan_name):
    createExportFolder(scan_name)
    CsvFileId = ExportCsvReport(scan_name)
    scheduleUuid = GetScanIdByName(scan_name)
    while True:
        url = f"https://cloud.tenable.com/scans/{scheduleUuid}/export/{CsvFileId}/download"
        headers = {
            'X-ApiKeys' : f'accessKey={apiaccesskey}; secretKey={apisecretkey}',
            'accept': "application/octet-stream",
            }
        CurrentExportStatus = CheckExportStatus(scan_name, CsvFileId)
        if CurrentExportStatus == 'ready':
            sendInfo = requests.request("GET", url, headers=headers)
            print("Downloading CSV Report...")
            newPdfReport = open(f"./Scans/{scan_name}/CSV Report.csv", "w+b")
            newPdfReport.write(sendInfo.content)
            newPdfReport.close()
            break
        else:
            time.sleep(5)
            

### Puts all the downloads together into one call function.
def GetAllScans(scan_name):
    GetExecutiveSummaryPdfExport(scan_name)
    GetByAssetPdfExport(scan_name)
    GetByPluginPdfExport(scan_name)
    GetCsvExport(scan_name)
    

### Calls the all downloads function above using the name at the top of the script.
GetAllScans(scan_name_for_exports)


    
