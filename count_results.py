#!/usr/bin/python3

import re

Debug = False
virusCount = {}

pasteLogFileName = 'pasteLog.txt'

# Open the log file created by process_pastebin.py
try:
    pasteLogFile = open( pasteLogFileName, 'r')
except Exception as e:
    print ("failed to open \"" + pasteLogFileName + "\": " + str(e))
    exit()

# Read in the log file.  ClamAV hits will be on a line.  If VirusTotal also
# has some hits, they will follow (on the same line).  Each virus name will be
# in quotes.  Incriment values in virusCount based on name found.

for input in pasteLogFile.readlines():
    if Debug: print (input.strip())
    isClamFound = re.search("(.+) Clam_found_malware\((\S+)\)(.*)", input.strip())
    if isClamFound:
        #print ("Clam found " + isClamFound.group(2) + " in " + isClamFound.group(1))
        if isClamFound.group(2) in virusCount:
            virusCount[isClamFound.group(2)] += 1
        else:
            virusCount[isClamFound.group(2)] = 1
        if isClamFound.group(3):
            for virusName in re.findall("\".+?\"", isClamFound.group(3)):
                virusName = virusName.replace("\"","")
                if virusName in virusCount:
                    virusCount[virusName] += 1
                else:
                    virusCount[virusName] = 1

# Now that we've read the entire log file, loop though the array and print
# how many times each virus name was encountered in the log file.

for virusName in virusCount.keys():
    print (virusCount[virusName], virusName)
