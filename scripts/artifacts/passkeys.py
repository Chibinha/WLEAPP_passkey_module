import os
import sys
import csv
from scripts.artifact_report import ArtifactHtmlReport
from scripts.ilapfuncs import logfunc, tsv, timeline, is_platform_windows, open_sqlite_db_readonly, does_table_exist
from bs4 import BeautifulSoup
from Evtx.Evtx import Evtx
from datetime import datetime
from regipy.registry import RegistryHive
from regipy.utils import convert_wintime

SEARCH_PATH = fr"\Software\Microsoft\Cryptography\FIDO"

class PasskeyLog:
    def __init__(self):
        self.userId = None
        self.transactionId = None
        self.type = None
        self.result = None
        self.timestamp = None
        self.computerName = None
        self.device = None
        self.website = None
        self.browser = None
        self.browserPath = None

    def set_event_type(self, value):
        self.type = value

    def set_timestamp(self, value):
        self.timestamp = value

    def set_transaction_id(self, value):
        self.transactionId = value

    def set_event_conclusion(self, value):
        self.result = value

    def set_user_id(self, value):
        self.userId = value

    def set_computer_name(self, value):
        self.computerName = value

    def set_device(self, value):
        self.device = value

    def set_website(self, value):
        self.website = value

    def set_browser(self, value):
        self.browser = value

    def set_browser_path(self, value):
        self.browserPath = value


def object_to_row(event):
    return [event.userId, event.transactionId, event.type, event.browser, event.browserPath,
            event.website, event.timestamp, event.computerName, event.device, event.result]

def get_passkeys(files_found, report_folder, seeker, wrap_text):
    passkey_logs = []
    for file_found in files_found:
        file_found = str(file_found)
        if os.path.basename(file_found) == "Microsoft-Windows-WebAuthN%4Operational.evtx":
            read_evtx(file_found, report_folder)
        elif os.path.basename(file_found) == "NTUSER.DAT":
            read_registry(file_found, report_folder)
    return

#files_found são os ficheiros a ler que previamente eram o "evtx_file_path"
def read_evtx(file_path, report_folder):
    reading = False
    event_list = []

    try:
        evtx = Evtx(file_path)
    except Exception as e:
        logfunc(f'Failed to open file {file_path} with error: {str(e)}')
        return

    with evtx:
        for record in evtx.records():

            soup = BeautifulSoup(record.xml(), 'xml')

            event_id = soup.find("EventID")
            if event_id:
                event_id = event_id.text

            #####################################
            # 1000: Start Registration          #
            # 1001: Registration Success        #
            # 1002: Failed/Canceled             #
            # 1003: Start Authentication        #
            # 1004: Authentication Success      #
            # 1005: Failed/Canceled             #
            # 1006: Start sending Ctap Cmd      #
            # 1007: Success Ctap Cmd            #
            # 1008: Connection failed           #
            #####################################

            if event_id in ["1000", "1003"]:
                event = PasskeyLog()

                transaction_id = soup.find("Data", attrs={'Name': 'TransactionId'})
                if transaction_id:
                    event.set_transaction_id(transaction_id.text)

                event.set_timestamp(record.timestamp())

                computer_name = soup.find("System")
                computer_name = computer_name.find("Computer")
                if computer_name:
                    event.set_computer_name(computer_name.text)

                user_id = soup.find("Security")
                user_id = user_id.get('UserID')
                if user_id:
                    event.set_user_id(user_id)

                event.set_event_type("Authentication" if event_id == "1003" else "Registration")
                reading = True
            elif event_id in ["1001", "1004"]:
                reading = False
                event.set_event_conclusion("Success")
                event_list.append((event.userId,event.transactionId,event.type,event.browser,event.browserPath,event.website,event.timestamp,event.computerName,event.device,event.result))
            elif event_id in ["1002", "1005"]:
                reading = False
                event.set_device("N/A")
                event.set_event_conclusion("Incomplete")
                event_list.append((event.userId,event.transactionId,event.type,event.browser,event.browserPath,event.website,event.timestamp,event.computerName,event.device,event.result))

            if reading and event_id == "2104" or event_id == "2106" or event_id == "1101" or event_id == "1103":

                event_data = soup.find("EventData")

                if event_data:

                    device_path = event_data.find("Data", attrs={'Name': 'DevicePath'})
                    rp_id = event_data.find("Data", attrs={'Name': 'RpId'})
                    image_name = event_data.find("Data", attrs={'Name': 'Name'})

                    if device_path:
                        event.set_device(device_path.text)
                        if device_path.text == "":
                            event.device = event.computerName

                    elif rp_id:
                        event.set_website(rp_id.text)

                    elif image_name:
                        if image_name.text == "ImageName":
                            data_value = event_data.find("Data", attrs={'Name': 'Value'})
                            if data_value:
                                event.set_browser_path(data_value.text)
                                event.set_browser(os.path.splitext(os.path.basename(event.browserPath))[0].capitalize())

    if len(event_list) > 0:
        report = ArtifactHtmlReport('Passkeys - Event Log')
        report.start_artifact_report(report_folder, 'Passkeys - Event Log')
        report.add_script()
        data_headers = ('userId', 'transaction_id', 'type', 'browser', 'browserPath', 'website', 'timestamp', 'computerName','device', 'result')

        report.write_artifact_data_table(data_headers, event_list, file_path)
        report.end_artifact_report()

        tsvname = f'Passkeys - Event Log'
        tsv(report_folder, data_headers, event_list, tsvname)
    else:
        logfunc('Passkeys - Event Log data available')

def read_registry(file_path, report_folder):
    reg = RegistryHive(file_path)
    fido_list = {}
    linked_devices = []  # [[<user_id>, <device_name>, <last_modified>, <isCorrupted>, <device_data>], ...]

    for sk in reg.get_key(SEARCH_PATH).iter_subkeys():
        fido_list[sk.name] = None

    for fido_sk in fido_list:
        device_list = {}

        path = rf'\Software\Microsoft\Cryptography\FIDO'
        path += f'\\' + str(fido_sk) + rf'\LinkedDevices'
        for device_sk in reg.get_key(path).iter_subkeys():
            device_list[device_sk.name] = None

        fido_list[fido_sk] = device_list.copy()

    for fido in fido_list:
        # print(fido)  # User ID
        linked_device = [fido, None, None, None, None]  # [<user_id>, <device_name>, <last_modified>, <isCorrupted>, <device_data>]

        device_element = []
        for device in fido_list[fido]:
            # print("\t" + device)
            device_element.append(device)

            path = rf'\Software\Microsoft\Cryptography\FIDO'
            path += f'\\' + str(fido) + rf'\LinkedDevices'
            path += f'\\' + str(device)
            data = reg.get_key(path)

            for i in data.get_values():
                # print("\t\t" + str(i))
                if i.name == "Name":
                    linked_device[1] = i.value
                if i.name == "Data" and i.value_type == 'REG_BINARY':
                    linked_device[4] = i.value.hex().upper()
                linked_device[3] = i.is_corrupted

            linked_device[2] = convert_wintime(data.header.last_modified, as_json=False)

            linked_devices.append(linked_device.copy())

    if len(linked_devices) > 0:
        report = ArtifactHtmlReport('Passkeys - registry')
        report.start_artifact_report(report_folder, 'Passkeys - registry')
        report.add_script()
        data_headers = ('User ID', 'Device Name', 'Device Data', 'Last Modified', 'is Corrupted')

        report.write_artifact_data_table(data_headers, linked_devices, file_path)
        report.end_artifact_report()

        tsvname = f'Passkeys - registry'
        tsv(report_folder, data_headers, linked_devices, tsvname)
    else:
        logfunc('Passkeys - registry data available')