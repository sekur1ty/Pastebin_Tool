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
import configparser
import gzip
import io

# define all the global variables here
stats = {}
statsFileName = '/home/del/Work/Pastebin/stats.txt'
logFileName = '/home/del/Work/Pastebin/pasteLog.txt'
regexFileName = '/home/del/Work/Pastebin/process_pastebin_regex.txt'
regexExcludeFileName = '/home/del/Work/Pastebin/process_pastebin_regex_exclude.txt'
pasteKeysSeen = {}
runDuration = -1
sleepDuration = -1
pasteLimit = -1
debug = False
debugFileName = "/tmp/process_pastebin-Debug.txt"
verboseOutput = False
doScanWithClam = True   # do we can new pastes with Clam AV
doSubmitHash2VirusTotal = True
doLimitVirusTotalHashes = True
doSearchRegEx = True  # do we check new pastes against a regEx
doLogRegExExcluded = True
regexToSearch = re.compile("")  # get's the compiled regex object
regexToExclude = re.compile("")  # get's the compiled regexToExclude object
commentRegex = re.compile("\s*#") # Any line starting with '#' is a comment
virusTotalAPIKey = ''
virusTotalCallTimes = [] # Array of last four times virutotal was called. Oldest at [0]

# define all the subroutines/functions we'll be using

def getConfigFile():
    global virusTotalAPIKey
    global doLogRegExExcluded

    debugPrint("Entering getConfigFile")
    config = configparser.ConfigParser()
    try:
        config.read_file(open('process_pastebin.ini'))
    except:
        debugPrint ("read of process_pastebin.ini failed:")
        print ("read of process_pastebin.ini failed, exiting")
        exit()
    if 'default' in config:
        if 'doLogRegExExcluded' in config['default']:
            doLogRegExExcluded = (config['default']['doLogRegExExcluded'] == 'True')
            debugPrint ("doLogRegExExcluded set to: \"" + str(doLogRegExExcluded) + "\"")

    if 'VirusTotal' in config:
        if 'virusTotalAPIKey' in config['VirusTotal']:
            virusTotalAPIKey = config['VirusTotal']['VirusTotalAPIKey']
            debugPrint ("virusTotalAPIKey set to: \"" + virusTotalAPIKey+"\"")

def getRegEx():
    global regexToSearch

    debugPrint("Entering getRegEx")
    regexToSearchString = ''
    if os.path.isfile(regexFileName):
        try:
            regexFile = open(regexFileName, 'r')
        except:
            debugPrint ("read of " + regexFileName + " failed:")
            print ("read of " + regexFileName + " failed, exiting")
            exit()

        for line in regexFile:
            if commentRegex.search(line):
                continue   # skip comments
            regexToSearchString += "(" + line.rstrip() + ")|"
        regexToSearchString = regexToSearchString.rstrip('|')  # lose the extra |
        debugPrint ("regexToSearchString: \"" + regexToSearchString + "\"")

        try:
            regexToSearch = re.compile(regexToSearchString)
        except:
            debugPrint ("re.compile of regexToSearchString failed")
            print ("re.compile of regular expression in " + regexFileName + " failed.")
            exit()
    else:
        print ("Couldn't find regEx file: " + regexFileName + ". Not doing regEx searches")
        # Just use default empty regEx

def getRegExExclusion():
    global regexToExclude

    debugPrint("Entering getRegExExclusion")
    regexToExcludeString = ''
    if os.path.isfile(regexExcludeFileName):
        try:
            regexExcludeFile = open(regexExcludeFileName, 'r')
        except:
            debugPrint ("open of " + regexExcludeFileName + " failed:")
            print ("open of " + regexExcludeFileName + " failed, exiting")
            exit()

        for line in regexExcludeFile:
            if commentRegex.search(line):
                continue   # skip comments
            regexToExcludeString += "(" + line.rstrip() + ")|"
        regexToExcludeString = regexToExcludeString.rstrip('|')  # lose the extra |
        debugPrint ("regexToExcludeString: \"" + regexToExcludeString + "\"")

        try:
            regexToExclude = re.compile(regexToExcludeString)
        except:
            debugPrint ("re.compile of regexToExcludeString failed")
            print ("re.compile of regular expression to exclude in " + regexExcludeFileName + " failed.")
            exit()
    else:
        print ("Couldn't find regEx Exclusion file: " + regexExcludeFileName + ". Not doing regEx exclusion")
        # Just use default empty regEx

def initDebug():
    global dbgFile
    if debug:
        dbgFile = open(debugFileName, "w")
        logTime = time.strftime("%x %X", time.localtime())
        dbgFile.write(logTime + ": " + "Starting Debug File" + "\n")
        dbgFile.flush()

def initLogFile():
    global logFile
    logFile = open(logFileName, "a")
    debugPrint ("log file " + logFileName + " is open")

def debugPrint(message):
    global dbgFile
    if debug:
        logTime = time.strftime("%x %X", time.localtime())
        dbgFile.write(logTime + ": " + message.rstrip() + "\n")  # with or without \n, output ends with \n
        dbgFile.flush()

def logPrint (message):
    global logFile
    logFile.write(message)
    logFile.flush()

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
    debugPrint ("writing Malware to: " + name + "\n")
    try:
        f = open(fileName, "wb")
        f.write(paste)
        f.close
    except:
        print ("Write to " + fileName + "failed")
        debugPrint ("Write to " + fileName + "failed")

def writeVirusTotalHitToFile(name, paste):
    # We have a special directory for pastes identified as malware by VT
    baseDir = "/home/del/Work/Pastebin/VirusTotal/"
    fileName = baseDir + name
    debugPrint ("writing Virus Total Hit to: " + name + "\n")
    try:
        f = open(fileName, "wb")
        f.write(paste)
        f.close
    except:
        print ("Write to " + fileName + "failed")
        debugPrint ("Write to " + fileName + "failed")

def writeRegexMatchToFile(name, paste):
    # We have a special directory for pastes identified as malware
    baseDir = "/home/del/Work/Pastebin/RegExMatch/"
    fileName = baseDir + name
    debugPrint ("writing regex match to: " + name + "\n")
    try:
        f = open(fileName, "wb")
        f.write(paste)
        f.close
    except:
        print ("Write regex match to " + fileName + "failed")
        debugPrint ("Write regex match to " + fileName + "failed")

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
    #parser.add_argument("rDuration", help="<Run Duration (minutes), \"0\" means never stop>", type=int)
    parser.add_argument("-r", "--runDuration", help="<Run Duration (minutes) - how long to run this program (\"0\", the default, means never stop)>", type=int, default = 0)
    #parser.add_argument("Duration", help="<Sleep Duration (seconds)>", type=int)
    parser.add_argument("-s", "--sleepDuration", help="<Sleep Duration (seconds) - how long to wait between queries (default is 60)>", type=int, default = 60)
    #parser.add_argument("pLimit", help="# pastes to request in each call", type=int)
    parser.add_argument("-p","--pasteLimit", help="# pastes to request in each query (default is 100)", type=int, default = 100)
    args = parser.parse_args()

    #runDuration = args.rDuration * 60  # convert from default minutes to seconds
    #sleepDuration = args.sDuration
    #pasteLimit = args.pLimit

    runDuration = args.runDuration * 60  # convert from default minutes to seconds
    sleepDuration = args.sleepDuration
    pasteLimit = args.pasteLimit
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
    if runDuration == 0:
        formattedRunDuration = "Until the end of time (or a system reboot, whichever comes first)"
    print ("runDuration: " + formattedRunDuration)
    print ("sleepDuration: " + str(sleepDuration) + " seconds")
    print ("pasteLimit: " + str(pasteLimit) + " pastes per query")
    print ("Progress codes:")
    print ("\"!\"\tFetch Failed\t\t\t\".\"\tSuccessful Fetch of pasteLimit pastes")
    print ("\"#\"\tBase64 detected\t\t\t\"C\"\tClamAV Detection")
    print ("\"(#)\"\tVirus Total # Detections\t\"s\"\tVirus Total scan is in progress")
    print ("\"R\"\tRegEx Detection\t\t\t\"E\"\tRegEx Exclusion")
    print ("\"Z\"\tZipped Content")
    print ("--------------------")

def logPasteFetchFailed():
    sys.stdout.write("!")
    sys.stdout.flush()

def logValidBase64():
    sys.stdout.write("#")
    sys.stdout.flush()

def logClamDetectedMaleware():
    sys.stdout.write("C")
    sys.stdout.flush()

def checkIfZipped(potential_zipped):
    debugPrint ("Entering checkIfZipped. Len of potential_zipped = " + str(len(potential_zipped)))
    # defend against unexpected data types
    if type(potential_zipped) is not bytes:
        debugPrint ('trying to encode potential_zipped. It is type: ' + str(type(potential_zipped)))
        potential_zipped = potential_zipped.encode('utf-8')
        debugPrint ("done encoding potential_zipped")

    fakeFile = io.BytesIO()
    fakeFile.write(potential_zipped)
    fakeFile.seek(0)
    with gzip.GzipFile(fileobj=fakeFile, mode='rb') as unzippedFile:
        try:
            gunzippedBytes = unzippedFile.read()
        except Exception as e:  # Apparently there are other rare failure modes
        #except OSError:  # not a gzipped file
            if e == OSError:
                debugPrint ("unzip failed, not a .gz file.  Returning False")
                return False, ''
            else:
        #except Excepton as e:  # Apparently there are other rare failure modes
                debugPrint ("unzip general failure: " +str(e))
                return False, ''

    debugPrint ("returning True.  Length of unzipped = " + str(len(gunzippedBytes)))
    #return True, gunzippedBytes.decode()
    return True, gunzippedBytes

def logRegExMatched():
    sys.stdout.write("R")
    sys.stdout.flush()

def logRegExExcluded():
    if doLogRegExExcluded:
        sys.stdout.write("E")
        sys.stdout.flush()

def logVirusTotalScanStillRunning():
    sys.stdout.write("s")
    sys.stdout.flush()

def logVirusTotalDetections(numberDetections):
    sys.stdout.write("(" + str(numberDetections) + ")")
    sys.stdout.flush()

def logZippedDetected():
    sys.stdout.write("Z")
    sys.stdout.flush()

def decodeBase64(key, data):
    global stats
    decoded = ''
    debugPrint ("Entering decodeBase64, key = " + str(key) + ", length of input data = " + str(len(data)))
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

def scanWithRegEx (key, data):
    global regexToSearch
    global stats
    startTime = time.time()
    debugPrint ("Entering scanWithRegEx, key = " + str(key) + ", length of input data = " + str(len(data)))

    #if (type(data) is str) and regexToSearch.search(data):
    regexSearchResult = regexToSearch.search(str(data))
    if regexSearchResult:
        matchingExpression = regexSearchResult.group()
        writeRegexMatchToFile(key, data)
        logRegExMatched()
        logPrint(" regEx_matched ("+matchingExpression+")")
        stats['malwareFilesSeen'] += 1

        debugPrint ("-----**** Infected File **** (RegEx Match) -\n")
        debugPrint ("Key: " + key + "MatchingExpression: " + matchingExpression +"\n")
        debugPrint ("--------------------------------------------\n")
        # todo - search regex groups to find what matched.
    debugPrint ("Exiting scanWithRegEx (%.3f)" % (time.time() - startTime))

def excludeWithRegEx (key, data):
    # Return true if we did exclude the paste
    global regexToExclude
    global stats
    startTime = time.time()
    debugPrint ("Entering excludeWithRegEx, key = " + str(key) + ", length of input data = " + str(len(data)))

    #if (type(data) is str) and regexToSearch.search(data):
    regexExcludeResult = regexToExclude.search(str(data))
    if regexExcludeResult:
        matchingExpression = regexExcludeResult.group()
        logRegExExcluded()
        logPrint(" regEx_excluded ("+matchingExpression+")")
        ##stats['regexExcludedCount'] += 1

        debugPrint ("-----**** Excluded File **** (RegEx Excluded) -\n")
        debugPrint ("Key: " + key + "  MatchingExpression: " + matchingExpression +"\n")
        debugPrint ("--------------------------------------------\n")

        return True
    debugPrint ("Exiting excludeWithRegEx (%.3f)" % (time.time() - startTime))
    return False

def scanWithClam(key, data):
    global stats
    startTime = time.time()
    debugPrint ("Entering scanWithClam, key = " + str(key) + ", length of input data = " + str(len(data)))
    # scan binries with Clam AV
    p = subprocess.Popen('clamscan -',stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        stdin=subprocess.PIPE,
        shell=True,
        bufsize=0)
    p.stdin.write(data)
    out = str(p.communicate()[0])
    scanInfo = ''
    if re.search(".*Infected\s+files:\s+0.*", out):
        infected = False
        scanInfo += out

    else:
        writeMalwareToFile(key, data)
        debugPrint ("-----**** Infected File **** ---------------\n")
        #debugPrint ("Full URL: " + fullUrl)
        debugPrint ("Key: " + key + "\n")
        debugPrint (str(out) + "\n")
        #print (out)
        debugPrint ("--------------------------------------------\n")
        malwareName = ''
        isMalwareName = re.search("stdin:\s+(.+)\s+FOUND", out)
        if isMalwareName:
            malwareName = isMalwareName.group(1)
        logClamDetectedMaleware()
        logPrint(" Clam_found_malware(" + malwareName + ")")
        stats['malwareFilesSeen'] += 1
    debugPrint ("Exiting scanWithClam (%.3f)" % (time.time() - startTime))
    # end scan with clamscan

def analyzeVirusTotalResult (result):
    debugPrint ("Entering analyzeVirusTotalResult\n")
    numberPositives = result['positives']
    allScans = result['scans']
    detectedCount = 0
    debugPrint ("Number positives: " + str(numberPositives) + "\n")
    debugPrint ("About to loop through results. There are " + str(len(allScans)) + " results. ")
    for scan in allScans.keys():
        scanName = scan
        resultString = ""
        detected = result['scans'][scan]['detected']
        if detected:
            detectedCount += 1
            resultString = ": result = \"" + result['scans'][scan]['result'] + "\""
            logPrint (" " + scan + ": \"" + result['scans'][scan]['result'] + "\"" )
        debugPrint ("     " + scanName + ": detected = " + str(detected) + resultString + "\n")
    debugPrint ("detectedCount = " + str(detectedCount))
    return detectedCount

def submitHash2VirusTotal (key, hash, pasteData):
    global virusTotalAPIKey
    global virusTotalCallTimes  # Array of last for times virutotal was called

    #print ("submitHash2VirusTotal: key = " + key + " hash = " + hash + "\n")
    # Determine if we've used up our 4 queries per minute
    startTime = time.time()
    debugPrint ("Entering SubmitHash2VirusTotal. key: " + str(key) + ", hash: " + str(hash))
    now = time.time()  # seconds since epoch
    virusTotalCallLimitExceeded = False
    if len(virusTotalCallTimes) == 4:
        if (now - virusTotalCallTimes[0]) <= 60:  # We've already done 4 calls within last minute
            virusTotalCallLimitExceeded = True
            print ("Exceeded Call Limit.  Key = " + key)
            debugPrint ("Exceeded Call Limit.  Key = " + key)
        virusTotalCallTimes[0:2] = virusTotalCallTimes[1:3]
        virusTotalCallTimes[3] = now
    else:
        virusTotalCallTimes.append(now) # popu;late first 4 times
    if virusTotalCallLimitExceeded:
        debugPrint ("virusTotalCallLimit has been Exceeded, skipping " + key)
        return

    #
    # Send the hash to virus total
    #

    url = 'https://www.virustotal.com/vtapi/v2/file/report'
    values = {'apikey' : virusTotalAPIKey,
              'resource' : hash}
    queryData = urllib.parse.urlencode(values)
    queryData = queryData.encode('ascii') # data should be bytes
    debugPrint("sendng request: queryData = " + str(queryData))
    req = urllib.request.Request(url, queryData)

    debugPrint ("about to read response")
    try:
        with urllib.request.urlopen(req) as response:
            the_page = response.read()
    except Exception as e:
        debugPrint ("HTTP request to Virus Total failed: " + str(e))
        return # Just quietly slink away
    try:
        jsonResult = json.loads(the_page)
    except json.decoder.JSONDecodeError:
        debugPrint ("---------- JSONDecodeError on the_page from Virus Total ------------")
        debugPrint (str(the_page))
        debugPrint ("--------------------------------------------------------------------")
        return # Just bail
    #print ("virus total response code: " + str(jsonResult['response_code']) + " message: " + jsonResult['verbose_msg'])
    if jsonResult['response_code'] == 1:  # Virus Total has seen this before
        debugPrint ("got a postive result from Virus Total\n")
        debugPrint (str(the_page) + "\n")
        logPrint(" positive_from_Virus_Total")
        numberDetections = analyzeVirusTotalResult(jsonResult)
        logPrint ("(" + str(numberDetections) + ")")
        logVirusTotalDetections(numberDetections)
        writeVirusTotalHitToFile(key, pasteData)
    elif jsonResult['response_code'] == -2: # already submitted and scan is still running
        debugPrint ("got a \"scan is still running\" (-2) from Virus Total")
        logVirusTotalScanStillRunning()   # really a placeholder until I write a wait-till-done
    #print (the_page)
    debugPrint("exiting SubmitHash2VirusTotal, response_code was: " + str(jsonResult['response_code']) + " (%.3f)" % (time.time() - startTime))
# This is the main processing routine
def main():

    global stats
    global pasteKeysSeen

    parseCmdArgs()
    initDebug()
    initLogFile()
    getConfigFile()
    getRegEx()
    getRegExExclusion()

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
        while (currentTime < doneTime) or (runDuration == 0):
            try:
                # Get a new list of available pastes
                #
                response = urllib.request.urlopen('https://scrape.pastebin.com/api_scraping.php?limit='+str(pasteLimit))
            except Exception as e:
                debugPrint ("urlopen(\'https://scrape.pastebin.com/api_scraping.php?limit=" + str(pasteLimit) + ")\' threw an exception: " + str(e))
                logPasteFetchFailed()
                time.sleep(5) # hopefully the Internet will reboot in a few seconds
                continue   # go try again

            newPasteList = response.read()
            # Parse the json from above into a python array.  Each element of the array
            # is a dictionary with data for a paste
            if len(newPasteList) > 0:
                try:
                    jsonResult = json.loads(newPasteList)
                    stats['totalFilesPresented'] += len(jsonResult)
                except json.decoder.JSONDecodeError:
                    print ("JSONDecodeError from Pastebin:")
                    print (newPasteList)
                    if 'Please slow down' in str(newPasteList):  # They're asking us to slow download
                        print ("pausing for 60 seconds at request of Pastebin ...")
                        time.sleep (60)
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

                # Check to see if we've seen this paste before - based on name
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
                    # First time for this paste content
                    sawFiles[pasteHash] = 1
                    logPrint ("\n" + str(key))
                    validBinary = False
                    fileToCheck = pasteData
                    # If it decodes e.g. base64, we'll call it a binary
                    if doDecodeBase64:
                        validBinary, decoded = decodeBase64(key, pasteData)
                    if validBinary:
                        decodedPasteHash = hashlib.sha256(decoded).hexdigest()
                        fileToCheck = decoded
                        if doScanWithClam:
                            scanWithClam(key, fileToCheck)
                        if doSubmitHash2VirusTotal:
                            submitHash2VirusTotal(key, decodedPasteHash, fileToCheck)
                        [isZipped, unZippedResult] = checkIfZipped (fileToCheck)
                        if isZipped:
                            logZippedDetected()
                            debugPrint ("We got a zipped paste! Length: " + str(len(unZippedResult)))
                            logPrint (" zipped(" + str((len(unZippedResult))) + ")")
                            fileToCheck = str(unZippedResult)
                    # irrespective of being binary or not, check for evil
                    if doSearchRegEx:
                        if not excludeWithRegEx (key, fileToCheck):
                            scanWithRegEx(key, fileToCheck)
                #  end for pasteObject in jsonResult

            # notify if we didn't get all we asked for, otherwise mark time
            if NumPastesThisTime != pasteLimit:
                print ("\nProcessed: " + str(NumPastesThisTime) + " pastes this time. Requested: " + str(pasteLimit))
            else:
                sys.stdout.write(".")
                sys.stdout.flush()

            currentTime = time.time()
            time.sleep(sleepDuration)
    except KeyboardInterrupt:
        pass

    # We're done collecting pastes.  Save Stats, and print summary
    currentTime = time.time()
    actualRunDuration = currentTime - startTime
    stats['mostRecentRunDuration'] = actualRunDuration
    stats['cumulativeRunDuration'] += actualRunDuration

    totalFilesSeen = 0
    for hash in sawFiles:
        totalFilesSeen += 1
        if sawFiles[hash] > stats['maxTimesSeenHashFiles']:
            stats['maxTimesSeenHashFiles'] = sawFiles[hash]

    writeStatsToFile()

    print ("\n--------------------")
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
