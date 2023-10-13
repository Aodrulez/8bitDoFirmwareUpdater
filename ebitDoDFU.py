# Inspired by fwupd project's ebitdo plugin (https://github.com/fwupd/fwupd/tree/main/plugins/ebitdo) 

import time
import os
import sys
import struct
import binascii
from ctypes import *
from numpy import sign
from array import array
import hid

# Definitions
FU_EBITDO_PKT_TYPE_USER_CMD  = 0x00
FU_EBITDO_PKT_TYPE_USER_DATA = 0x01
FU_EBITDO_PKT_TYPE_MID_CMD   = 0x02

FU_EBITDO_PKT_CMD_FW_UPDATE_DATA       = 0x00  # update firmware data 
FU_EBITDO_PKT_CMD_FW_UPDATE_HEADER     = 0x01  # update firmware header 
FU_EBITDO_PKT_CMD_FW_UPDATE_OK         = 0x02	# mark update as successful 
FU_EBITDO_PKT_CMD_FW_UPDATE_ERROR      = 0x03   # update firmware error 
FU_EBITDO_PKT_CMD_FW_GET_VERSION       = 0x04  # get cur firmware vision 
FU_EBITDO_PKT_CMD_FW_SET_VERSION       = 0x05  # set firmware version 
FU_EBITDO_PKT_CMD_FW_SET_ENCODE_ID     = 0x06  # set app firmware encode ID 
FU_EBITDO_PKT_CMD_ACK                  = 0x14	# acknowledge 
FU_EBITDO_PKT_CMD_NAK                  = 0x15	# negative acknowledge 
FU_EBITDO_PKT_CMD_UPDATE_FIRMWARE_DATA = 0x16  # update firmware data 
FU_EBITDO_PKT_CMD_TRANSFER_ABORT       = 0x18  # aborts transfer 
FU_EBITDO_PKT_CMD_VERIFICATION_ID      = 0x19  # verification id (only BT?) 
FU_EBITDO_PKT_CMD_GET_VERIFICATION_ID  = 0x1a  # verification id (only BT) 
FU_EBITDO_PKT_CMD_VERIFY_ERROR         = 0x1b	# verification error 
FU_EBITDO_PKT_CMD_VERIFY_OK            = 0x1c	# verification successful 
FU_EBITDO_PKT_CMD_TRANSFER_TIMEOUT     = 0x1d  # send or receive data timeout 
FU_EBITDO_PKT_CMD_GET_VERSION          = 0x21	# get fw ver, joystick mode 
FU_EBITDO_PKT_CMD_GET_VERSION_RESPONSE = 0x22  # get fw version response 


APP_KEY_INDEX = [0x186976e5, 0xcac67acd, 0x38f27fee, 0x0a4948f1, 0xb75b7753, 0x1f8ffa5c,
 0xbff8cf43, 0xc4936167, 0x92bd03f0, 0x5573c6ed, 0x57d8845b, 0x827197ac, 0xb91901c9, 0x3917edfe, 0xbcd6344f,0xcf9e23b5]

# Device specific
bootloaderVID1 = 0x0483
bootloaderVID2 = 0x2DC8
bootloaderPID1 = 0x5750
bootloaderPID2 = 0x3208
deviceSerial  = []

# 8bitDo Header
firmwareHeader          = []
firmwareVersion         = 0x00
firmwareDestinationAddr = 0x00
firmwareSize            = 0x00
firmwareData            = []
    
# Packet type
pktType = [
{ "type" : 0x00, "typeName" : "UserCmd" },
{ "type" : 0x01, "typeName" : "UserData" },
{ "type" : 0x02, "typeName" : "MidCmd " },
]
    
# Packet command
pktCMD = [
{ "cmd" : 0x00, "cmdName" : "FwUpdateData" },
{ "cmd" : 0x01, "cmdName" : "FwUpdateHeader" },
{ "cmd" : 0x02, "cmdName" : "FwUpdateOk" },
{ "cmd" : 0x03, "cmdName" : "FwUpdateError" },
{ "cmd" : 0x04, "cmdName" : "FwGetVersion" },
{ "cmd" : 0x05, "cmdName" : "FwSetVersion" },
{ "cmd" : 0x06, "cmdName" : "FwSetEncodeId" },
{ "cmd" : 0x14, "cmdName" : "Ack" },
{ "cmd" : 0x15, "cmdName" : "Nack" },
{ "cmd" : 0x16, "cmdName" : "UpdateFirmwareData" },
{ "cmd" : 0x18, "cmdName" : "TransferAbort" },
{ "cmd" : 0x19, "cmdName" : "VerificationId" },
{ "cmd" : 0x1a, "cmdName" : "GetVerificationId" },
{ "cmd" : 0x1b, "cmdName" : "VerifyError" },
{ "cmd" : 0x1c, "cmdName" : "VerifyOk" },
{ "cmd" : 0x1d, "cmdName" : "TransferTimeout" },
{ "cmd" : 0x21, "cmdName" : "GetVersion" },
{ "cmd" : 0x22, "cmdName" : "GetVersionResponse" },
]

def makeWord(hiByte, loByte):
    word=(hiByte << 8) + loByte
    return(word)
 
def swap32(i):
    return struct.unpack("<I", struct.pack(">I", i))[0]
        
def getCMDName(cmd):
    for i in range(0,len(pktCMD)):
        if (cmd == pktCMD[i]['cmd']):
            return(pktCMD[i]['cmdName'])
    print(" [-] Unknown command")
    
def getPKTType(cmd):
    for i in range(0,len(pktType)):
        if (cmd == pktType[i]['type']):
            return(pktType[i]['typeName'])
    print(" [-] Unknown packet type")
    


def parsePacket(data):
    packet=[]
    packetLength = data[0]
    packetType = data[1]
    cmdSubtype = data[2]
    cmdLength  = makeWord(data[4], data[3])
    cmd        = data[5]
    payloadLen = makeWord(data[7], data[6])
    packet=[packetLength, packetType, cmdSubtype, cmdLength, cmd, payloadLen]
    if (payloadLen > 0):
        for x in range (0, payloadLen):
            packetData = data[8 + x]
            print(packetData)
            packet.append(packetData)
        
    return(packet)
    

def parseResponsePacket(dev):
    global deviceSerial
    data = []
    
    
    while True:
            data = dev.read(0x40)
            if data:
                break 
    
    if not data:
        print(" [-] No response from device")
        return(False)
            
    packet=[]
    payloadData = []
    packetLength = data[0]
    packetType = data[1]
    cmdSubType = data[2]
    cmdLength  = makeWord(data[4], data[3])
    cmd        = data[5]
    
    #get-version (bootloader)
    if (packetType == FU_EBITDO_PKT_TYPE_USER_CMD and cmdSubType == FU_EBITDO_PKT_CMD_UPDATE_FIRMWARE_DATA and cmd == FU_EBITDO_PKT_CMD_FW_GET_VERSION):
        #print(" Command FW_GET_VERSION")
        payloadLen = makeWord(data[7], data[6])
        if (payloadLen > 0):
            for x in range (0, payloadLen):
                payloadData = data[8 + x]
            
            return(payloadData)
        else:
            print(" [-] Get-version (bootloader) payload too small")
        
        
    # get-version (firmware) -- not a packet, just raw data
    if (packetLength == FU_EBITDO_PKT_CMD_GET_VERSION_RESPONSE):
        #print(" Command CMD_GET_VERSION_RESPONSE")
        #data.pop(0) 
        return(data)

    
    # verification-id response
    if (packetType == FU_EBITDO_PKT_TYPE_USER_CMD and cmdSubType == FU_EBITDO_PKT_CMD_VERIFICATION_ID):
        #print(" Command FU_EBITDO_PKT_CMD_VERIFICATION_ID")
        payloadLen = makeWord(data[4], data[3])
        if (payloadLen > 0):
            deviceSerial = []
            for x in range (0, payloadLen, 4):
                payloadData = bytearray(data[5 + x:5 + x+ 4])
                deviceSerial.append(struct.unpack("<i",payloadData)[0])
            
            #dumpPacketDetails(packet)
            return(True)
        else:
            print(" [-] Verification-id response payload too small")
            return(False)

    
    # update-firmware-data
    if (packetType == FU_EBITDO_PKT_TYPE_USER_CMD and cmdSubType == FU_EBITDO_PKT_CMD_UPDATE_FIRMWARE_DATA):
        #print(" Command CMD_UPDATE_FIRMWARE_DATA")
        payloadLen = makeWord(data[7], data[6])
        
        if (payloadLen == 0 and cmd == FU_EBITDO_PKT_CMD_ACK):
            #print(" Command CMD_UPDATE_FIRMWARE_DATA Ack") 
            return(True)
        else:
            print(" [-] Command CMD_UPDATE_FIRMWARE_DATA failed")
            
        
    return(False)


def readFirmwareFile(updateFileName):
    with open(updateFileName, "rb") as updateFile:
        tempfirmwareData=updateFile.read()
    updateFile.close()
    
    global firmwareHeader
    global firmwareVersion
    global firmwareDestinationAddr
    global firmwareSize
    global firmwareData
    
    
    firmwareHeader=tempfirmwareData[0:0x1c]
    firmwareVersion=struct.unpack("<i", tempfirmwareData[0:4])[0]
    firmwareDestinationAddr=struct.unpack("<i", tempfirmwareData[4:8])[0]
    firmwareSize=struct.unpack("<i", tempfirmwareData[8:12])[0]
    firmwareData = tempfirmwareData[0x1c:]

    print("\t Firmware version: "+str(firmwareVersion))
    print("\t Target Address: "+hex(firmwareDestinationAddr))
    print("\t Size: "+hex(firmwareSize)+" bytes")
    

   
def dumpPacketDetails(packet):
    print(" Packet length : " + hex(packet[0]))
    print(" Packet type   : " + getPKTType(packet[1]))
    print(" CMD subtype   : " + getCMDName(packet[2]))
    print(" CMD length    : " + hex(packet[3]))
    print(" Command       : " + getCMDName(packet[4]))
 
    payloadLen = 0
    if (packet[5]):
        payloadLen = int(packet[5])    
    payload = []
    if (payloadLen > 0):
        for x in range (0, payloadLen):
            payload.append(packet[6 + x])


def createPacket(packetType, cmdSubType, cmd=0x00, payload=0):
    payloadSize = len(payload)
    if payloadSize > (64 - 8):
        print(" [-] Input payload too large")
    packet = []
    
    
    if (payloadSize > 0):
        packetLength = 7 + len(payload) # packet header is 8 bytes in size
        packet = [ packetLength, packetType, cmdSubType ]
        cmdLength = payloadSize + 3
        packet.append(cmdLength)
        packet.append(0x00)
        packet.append(cmd)
        packet.append(payloadSize)
        packet.append(0x00)
        for x in range (0, payloadSize):
            packet.append(payload[x])
        if (packetLength != len(packet)-1):
            print(" [-] Packet length is incorrect")
            
    else:
        packetLength = 5 # packet header is 5 bytes in size for just commands
        packet = [ packetLength, packetType, cmdSubType ]
        cmdLength = payloadSize + 1
        packet.append(cmdLength)
        packet.append(0x00)
        packet.append(cmd)
        if (packetLength != len(packet)-1 ):
            print(" [-] Packet length is incorrect")
    
    return(packet)
    
   
def sendPacket(dev, packetType, cmdSubType, cmd=0x00, payload=[]):
    tempPacket = createPacket(packetType, cmdSubType, cmd, payload)
    dev.write([0x0] + tempPacket)
    
    
def firmwareUpdate(dev):

    # Get device serial first
    global deviceSerial
    sendPacket(dev, FU_EBITDO_PKT_TYPE_USER_CMD, FU_EBITDO_PKT_CMD_GET_VERIFICATION_ID)
    response = parseResponsePacket(dev)
    
    if (response == False):
        print(" [-] Failed to fetch device verification-id, update failed")
        return (False)
    
    # Construct response for verification after firmware data is sent
    serialNew    = [0x00, 0x00, 0x00]
    tempArray    = []
    serialNew[0] = (deviceSerial[0] ^ APP_KEY_INDEX[deviceSerial[0] & 0x0f])
    serialNew[1] = (deviceSerial[1] ^ APP_KEY_INDEX[deviceSerial[1] & 0x0f])
    serialNew[2] = (deviceSerial[2] ^ APP_KEY_INDEX[deviceSerial[2] & 0x0f])
    
    for x in range (0,3):
        tempArray.append((serialNew[x] ) & 0xff)
        tempArray.append((serialNew[x] >> 8) & 0xff)
        tempArray.append((serialNew[x] >> 16) & 0xff)
        tempArray.append((serialNew[x] >> 24) & 0xff)
    serialNew = tempArray
     
    # Initialize by sending header
    sendPacket(dev, FU_EBITDO_PKT_TYPE_USER_CMD, FU_EBITDO_PKT_CMD_UPDATE_FIRMWARE_DATA, FU_EBITDO_PKT_CMD_FW_UPDATE_HEADER, firmwareHeader)
    response = parseResponsePacket(dev)
    
    if (response == False):
        print(" [-] Failed to initialize firmware update routine, update failed")
        return (False)
    
    # Send rest of the firmware in 32 byte blocks
    for x in range (0, firmwareSize, 32):
    
        dataBlock = firmwareData[x:x+32]
        sendPacket(dev, FU_EBITDO_PKT_TYPE_USER_CMD, FU_EBITDO_PKT_CMD_UPDATE_FIRMWARE_DATA, FU_EBITDO_PKT_CMD_FW_UPDATE_DATA, dataBlock)
        response = parseResponsePacket(dev)
        if (response == False):
            print(" [-] Failed to send firmware data block, update failed")
            return (False)
    
    # Set the encode-id with SerialNew, seems to response is expected from Device
    sendPacket(dev, FU_EBITDO_PKT_TYPE_USER_CMD, FU_EBITDO_PKT_CMD_UPDATE_FIRMWARE_DATA, FU_EBITDO_PKT_CMD_FW_SET_ENCODE_ID, serialNew)
    response = parseResponsePacket(dev)
    if (response == False):
        print(" [-] Failed to set encode-id, update failed")
        return (False)
     
    # Mark flash as successful
    sendPacket(dev, FU_EBITDO_PKT_TYPE_USER_CMD, FU_EBITDO_PKT_CMD_UPDATE_FIRMWARE_DATA, FU_EBITDO_PKT_CMD_FW_UPDATE_OK)

    print(" [+] Firmware updated successfully")
    

def main():
    print("\t +---------------------------+")
    print("\t |  8bitDo Firmware Updater  |")
    print("\t +---------------------------+")
    print("\t (c) Aodrulez\n")
    
    if len(sys.argv) < 2:
        print(" [-] Usage : "+sys.argv[0]+" updateFileName.dat\n")
        quit()
    sys.argv[1]
    print(" [+] Firmware file: "+sys.argv[1])
        
    # device setup
    ebitDoDevice = hid.device()
    ebitDoDeviceVID = 0x0
    ebitDoDevicePID = 0x0

    for device_dict in hid.enumerate():
        if ((device_dict['vendor_id'] == bootloaderVID1 or device_dict['vendor_id'] == bootloaderVID2) and (device_dict['product_id'] == bootloaderPID1 or device_dict['product_id'] == bootloaderPID2)):
            print(" [+] Found an 8BitDo device in bootloader mode")
            ebitDoDeviceVID = device_dict['vendor_id']
            ebitDoDevicePID = device_dict['product_id']
            print("\t VID     : "+hex(ebitDoDeviceVID))
            print("\t PID     : "+hex(ebitDoDevicePID))
            print("\t Product : "+str(device_dict['product_string']))
            break
    if (ebitDoDevicePID == 0x0):
        print(" [-] Found no 8BitDo device in bootloader mode.\n")
        quit()

    ebitDoDevice.open(ebitDoDeviceVID, ebitDoDevicePID) 
    ebitDoDevice.set_nonblocking(1)
    
    # Initiate firmware update
    print(" [+] Initiating firmware update")
    readFirmwareFile(sys.argv[1])
    print(" [+] Updating..")
    firmwareUpdate(ebitDoDevice)
    
    
main()
