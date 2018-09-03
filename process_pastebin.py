#!/usr/bin/python3

import urllib.request
import urllib.parse
import json
import hashlib
import time
import sys
import subprocess
import os
import base64
import re
import argparse

# define all the global variables here
stats = {}
statsFileName = '/home/del/Work/Pastebin/stats.txt'
pasteKeysSeen = {}
runDuration = -1
sleepDuration = -1
pasteLimit = -1
debug = False
debugFileName = "/tmp/process_pastebin-Debug.txt"
verboseOutput = False

# define all the subroutines/functions we'll be using

def initDebug():
    global dbgFile
    if debug:
        dbgFile = open(debugFileName, "w")
        logTime = time.strftime("%x %X", time.localtime())
        dbgFile.write(logTime + ": " + "Starting Debug File" + "\n")
        dbgFile.flush()


def debugPrint(message):
    global dbgFile
    if debug:
        logTime = time.strftime("%x %X", time.localtime())
        dbgFile.write(logTime + ": " + message + "\n")
        dbgFile.flush()

def writeStatsToFile():
    global stats
    global statsFileName
    output = json.dumps(stats)
    try:
        statsFile = open(statsFileName, 'w')
        statsFile.write(output)
        statsFile.close()
    except:
        print ("writing stats to " + statsFileName + " failed")

def readStatsFromFile():
    global stats

    if os.path.isfile(statsFileName):
        statsFile = open(statsFileName, 'r')
        input = statsFile.read()
        stats = json.loads(input)
    else:
        print ("Couldn't find stats file: " + statsFileName)

def writePasteToFile(name, paste):
    # write paste to the "Pastes" directory
    debugPrint ("Entering writePasteToFile (" + name + ")")
    baseDir = "/home/del/Work/Pastebin/Pastes/"
    fileName = baseDir + name
    try:
        f = open(fileName, "wb")
        f.write(paste)
        f.close
    except:
        print ("Write to " + fileName + "failed")

def writeDecodedBase64PasteToFile(name, paste):
    # write decoded paste to a separate directory
    debugPrint ("Entering writeDecodedBase64PasteToFile (" + name + ")")
    baseDir = "/home/del/Work/Pastebin/DecodedBase64Pastes/"
    fileName = baseDir + name
    try:
        f = open(fileName, "wb")
        f.write(paste)
        f.close
    except:
        print ("Write to " + fileName + "failed")

def writeMalwareToFile(name, paste):
    # We have a special directory for pastes identified as malware
    baseDir = "/home/del/Work/Pastebin/Malware/"
    fileName = baseDir + name
    #print ("writing malware to: " + fileName)
    try:
        f = open(fileName, "wb")
        f.write(paste)
        f.close
    except:
        print ("Write to " + fileName + "failed")

def parseCmdArgs():
    global runDuration
    global sleepDuration
    global pasteLimit
    global debug
    global verboseOutput

    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
        action="store_true")
    parser.add_argument("-d", "--debug", help="turn on debug output",
        action="store_true")
    parser.add_argument("rDuration", help="<Run Duration (minutes)>", type=int)
    parser.add_argument("sDuration", help="<Sleep Duration (seconds)>", type=int)
    parser.add_argument("pLimit", help="# pastes to request in each call", type=int)
    args = parser.parse_args()

    runDuration = args.rDuration * 60
    sleepDuration = args.sDuration
    pasteLimit = args.pLimit
    debug = args.debug
    verboseOutput = args.verbose


def printStartMessage():
    global runDuration
    global sleepDuration
    global pasteLimit
    global debug
    global verboseOutput

    print ("Starting")
    formattedRunDuration = str(runDuration) + " seconds"
    if runDuration > 60:
        formattedRunDuration = "Around " + "%.3f" % (runDuration/60) + " minutes"
    if runDuration > 3600:
        formattedRunDuration = "Around " + "%.3f" % (runDuration/3600) + " hours"
    print ("runDuration: " + formattedRunDuration)
    print ("sleepDuration: " + str(sleepDuration) + " seconds")
    print ("pasteLimit: " + str(pasteLimit) + " pastes per query")
    print ("--------------------")

def logPasteFetchFailed():
    sys.stdout.write("!")
    sys.stdout.flush()

def logValidBase64():
    sys.stdout.write("#")
    sys.stdout.flush()


def decodeBase64(key, data):
    global stats
    decoded = ''
    debugPrint ("Entering decodeBase64, length of input data = " + str(len(data)))
    if not re.search('\s|http', str(data)):  # rule out trivial cases
        debugPrint ("... ruled out trivial case, trying to decode")
        try:
            decoded = base64.b64decode(data, validate=False)
            debugPrint("... looks like we have a winner")
            validBinary = True
            #stats['validBase64Pastes'] += 1
            writePasteToFile(key, data)
            writeDecodedBase64PasteToFile(key, decoded)
            logValidBase64()
        except Exception as e:
            debugPrint ("got exception from b64decode: " + str(e))
            validBinary = False
    else:
        validBinary = False
    debugPrint ("Exiting decodeBase64,  validBinary = " + str(validBinary))
    return [validBinary, decoded]

def main():

    global stats
    global pasteKeysSeen

    parseCmdArgs()

    initDebug()

    sawFiles = {}
    stats['duplicatePastes'] = 0
    stats['malwareFilesSeen'] = 0
    stats['totalFilesPresented'] = 0
    doDecodeBase64 = True
    stats['validBase64Pastes'] = 0
    stats['cumulativeRunDuration'] = 0
    stats['maxTimesSeenHashFiles'] = 0
    duplicateKeys = 0

    startTime = time.time()   # seconds since epoch
    doneTime = startTime + runDuration  # When we should be done
    currentTime = time.time()

    readStatsFromFile()  # this allows stats to persist across multiple runs of this program

    printStartMessage()

    # Here is where we loop, downloading pastes.
    # First we get a list of available pastes. Then we download each of those
    # pastes.  We calculate a hash for each paste to use as an id - and move on if
    # the paste is a duplicate

    try:
        while currentTime < doneTime:
            # Get a new list of available pastes
            with urllib.request.urlopen('https://scrape.pastebin.com/api_scraping.php?limit='+str(pasteLimit)) as response:
                newPasteList = response.read()

            # Parse the json from above into a python array.  Each element of the array
            # is a dictionary with data for a paste
            if len(newPasteList) > 0:
                try:
                    jsonResult = json.loads(newPasteList)
                    stats['totalFilesPresented'] += len(jsonResult)
                except json.decoder.JSONDecodeError:
                    print ("JSONDecodeError")
                    print (newPasteList)
                    continue
            else:
                continue

            NumPastesThisTime = 0
            #loop through all the new pastes, store their hashes to count
            for pasteObject in jsonResult:
                NumPastesThisTime += 1
                fullUrl = pasteObject['full_url']
                key = pasteObject['key']
                title = pasteObject['title']

                # Check to see if we've seen this paste before
                if key in pasteKeysSeen:
                    duplicateKeys += 1
                    pasteKeysSeen[key] += 1
                    continue  # don't bother with downloading and processing
                pasteKeysSeen[key] = 1

                # I'm getting connection reset from pastebin.  slow down a bit ...
                time.sleep(.3)

                # Get the contents of the paste
                try:
                    with urllib.request.urlopen('https://scrape.pastebin.com/api_scrape_item.php?i=' + key) as response:
                        pasteData = response.read()
                        #print (pasteData)
                except Exception as e:
                    logPasteFetchFailed()
                    debugPrint("Fetch of paste \"" + key + "\" failed: " + str(e))
                    continue

                # Calculate the hash of the paste
                pasteHash = hashlib.sha256(pasteData).hexdigest()

                # Don't process this paste if it's a duplicate of one we've seen before
                if pasteHash in sawFiles:
                    sawFiles[pasteHash] += 1
                    stats['duplicatePastes'] += 1
                else:
                    # First time for this paste
                    sawFiles[pasteHash] = 1
                    validBinary = False
                    if doDecodeBase64:
                        validBinary, decoded = decodeBase64(key, pasteData)
                    if validBinary:
                        #print ("Got a valid binary: " + str(key))
                        #p = subprocess.Popen('cat > ' + key + '.bin',stdout=subprocess.PIPE,
                        p = subprocess.Popen('clamscan -',stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT,
                            stdin=subprocess.PIPE,
                            shell=True,
                            bufsize=0)
                        p.stdin.write(decoded)
                        out = str(p.communicate()[0])
                        #print ("result from clamcan: " + str(out))
                        scanInfo = ''
                        if re.search(".*Infected\s+files:\s+0.*", out):
                            infected = False
                            scanInfo += out
                            sys.stdout.write(".")
                            sys.stdout.flush()

                        else:
                            writeMalwareToFile(key, decoded)
                            #print ('-----**** Infected File **** ---------------')
                            #print ("Full URL: " + fullUrl)
                            #print ("Key: " + key)
                            #print ("Title: " + title)
                            #print (out)
                            #print ('--------------------------------------------')
                            sys.stdout.write("M")
                            sys.stdout.flush()
                            stats['malwareFilesSeen'] += 1
                #  end for pasteObject in jsonResult

            # notify if we didn't get all we asked for, otherwise mark time
            if NumPastesThisTime != pasteLimit:
                print ("\nProcessed: " + str(NumPastesThisTime) + " pastes this time")
            else:
                sys.stdout.write(".")
                sys.stdout.flush()

            currentTime = time.time()
            time.sleep(sleepDuration)
    except KeyboardInterrupt:
        pass

    currentTime = time.time()
    actualRunDuration = currentTime - startTime
    stats['mostRecentRunDuration'] = actualRunDuration
    stats['cumulativeRunDuration'] += actualRunDuration

    totalFilesSeen = 0
    for hash in sawFiles:
        totalFilesSeen += 1
        if sawFiles[hash] > stats['maxTimesSeenHashFiles']:
            stats['maxTimesSeenHashFiles'] = sawFiles[hash]

    print ("\n--------------------")
    writeStatsToFile()
    formattedRunDuration = str(actualRunDuration) + " seconds"
    if actualRunDuration > 60:
        formattedRunDuration = "Around " + "%.3f" % (actualRunDuration/60) + " minutes"
    if actualRunDuration > 3600:
        formattedRunDuration = "Around " + "%.3f" % (actualRunDuration/3600) + " hours"

    formattedCumulativeRunDuration = str(stats['cumulativeRunDuration']) + " seconds"
    if stats['cumulativeRunDuration'] > 60:
        formattedCumulativeRunDuration = "Around " + "%.3f" % (stats['cumulativeRunDuration']/60) + " minutes"
    if stats['cumulativeRunDuration'] > 3600:
        formattedCumulativeRunDuration = "Around " + "%.3f" % (stats['cumulativeRunDuration']/3600) + " hours"

    print ("Run Duration: " + formattedRunDuration)
    print ("sleepDuration: " + str(sleepDuration) + " seconds")
    print ("pasteLimit: " + str(pasteLimit) + " pastes per query")
    print ("Number of Files Available: " + str(stats['totalFilesPresented']))
    print ("Total Unique Files Seen: " + str(totalFilesSeen))
    print ("Duplicate Pastes seen: " + str(stats['duplicatePastes']))
    print ("Duplicate paste keys this run: " + str(duplicateKeys))
    print ("Valid base64 pastes seen: " + str(stats['validBase64Pastes']))
    print ("Malware pastes seen: " + str(stats['malwareFilesSeen']))
    print ("Max file occurrance: " + str(stats['maxTimesSeenHashFiles']))
    print ("Cumulative run time: " + formattedCumulativeRunDuration)
    print ("Average Unique Files/min: " + str(totalFilesSeen/(actualRunDuration/60)))


if __name__ == "__main__":
    main()
