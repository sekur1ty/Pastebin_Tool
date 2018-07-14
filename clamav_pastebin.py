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

def writePasteToFile(name, paste):
    # write paste to the "Pastes" directory
    baseDir = "/home/del/Work/Pastebin/Pastes/"
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

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-v", "--verbose", help="increase output verbosity",
        action="store_true")
    parser.add_argument("-d", "--debug", help="turn on debug output",
        action="store_true")
    if len(sys.argv) == 4:
        runDuration = int(sys.argv[1]) * 60
        sleepDuration = int(sys.argv[2])
        pasteLimit = int(sys.argv[3])
    else:
        print ("Usage: " + sys.argv[0] + "<Run Duration (Minutes)> <Sleep Duration (Seconds)> <pasteLimit (# pastes in each call)>")
        exit()

    sawFiles = {}
    duplicatePastes = 0
    malwareFilesSeen = 0
    totalFilesPresented = 0
    doDecodeBase64 = True
    validBase64Pastes = 0

    startTime = time.time()   # seconds since epoch
    doneTime = startTime + runDuration  # When we should be done
    currentTime = time.time()

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

    try:
        while currentTime < doneTime:
            with urllib.request.urlopen('https://scrape.pastebin.com/api_scraping.php?limit='+str(pasteLimit)) as response:
                newPasteList = response.read()

            # Parse the json from above into a python array.  Each element of the array
            # is a dictionary with data for a paste
            if len(newPasteList) > 0:
                try:
                    jsonResult = json.loads(newPasteList)
                    totalFilesPresented += len(jsonResult)
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

                # I'm getting connection reset from pastebin.  slow down a bit ...
                time.sleep(.3)

                # Get the contents of the paste
                try:
                    with urllib.request.urlopen('https://scrape.pastebin.com/api_scrape_item.php?i=' + key) as response:
                        pasteData = response.read()
                        #print (pasteData)
                except:
                    sys.stdout.write("!")
                    sys.stdout.flush()
                    continue

                # Calculate the hash of the paste
                pasteHash = hashlib.sha256(pasteData).hexdigest()

                # Don't run clamav if we've already seen this one
                if pasteHash in sawFiles:
                    sawFiles[pasteHash] += 1
                    duplicatePastes += 1
                else:
                    # First time for this hash
                    sawFiles[pasteHash] = 1
                    if doDecodeBase64:
                        if not re.search('\s|http', str(pasteData)):  # rule out trivial cases
                            try:
                                decoded = base64.b64decode(pasteData, validate=False)
                                validBinary = True
                                validBase64Pastes += 1
                                writePasteToFile(key, pasteData)
                                sys.stdout.write("#")
                                sys.stdout.flush()
                            except:
                                validBinary = False
                        else:
                            validBinary = False
                    else:
                        decoded = pasteData  # if didn't ask for base64 decode, just use pastedata
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
                            malwareFilesSeen += 1
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
    maxTimesSeen = 0
    totalFilesSeen = 0
    for hash in sawFiles:
        totalFilesSeen += 1
        if sawFiles[hash] > maxTimesSeen:
            maxTimesSeen = sawFiles[hash]

    print ("\n--------------------")
    formattedRunDuration = str(actualRunDuration) + " seconds"
    if actualRunDuration > 60:
        formattedRunDuration = "Around " + "%.3f" % (actualRunDuration/60) + " minutes"
    if actualRunDuration > 3600:
        formattedRunDuration = "Around " + "%.3f" % (actualRunDuration/3600) + " hours"
    print ("Run Duration: " + formattedRunDuration)
    print ("sleepDuration: " + str(sleepDuration) + " seconds")
    print ("pasteLimit: " + str(pasteLimit) + " pastes per query")
    print ("Number of Files Available: " + str(totalFilesPresented))
    print ("Total Unique Files Seen: " + str(totalFilesSeen))
    print ("Duplicate Pastes seen: " + str(duplicatePastes))
    print ("Valid base64 pastes seen: " + str(validBase64Pastes))
    print ("Malware pastes seen: " + str(malwareFilesSeen))
    print ("Max file occurrance: " + str(maxTimesSeen))
    print ("Average Unique Files/min: " + str(totalFilesSeen/(actualRunDuration/60)))


if __name__ == "__main__":
    main()
