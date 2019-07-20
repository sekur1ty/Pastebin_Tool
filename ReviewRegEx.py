#!/usr/bin/python3

import re
import os
import sys
import termios
import fcntl
# pip install readchar

Debug = False

# This program provides a relatively efficient way to sort through all the files
# collected by the RegEx matcher in the Pastebin scraper, "process_pastebin.py".
# Provide a keystroke based interface what provides the option to view a file in
# less, and then either save as interesting, or dispose of it.

regExDir = '/home/del/Work/Pastebin/RegExMatch/'
interestingDir = '/home/del/Work/Pastebin/InterestingRegEx/'
ignoreDir = '/home/del/Work/Pastebin/IgnoreRegEx/'


# This is stolen from http://love-python.blogspot.com/2010/03/getch-in-python-get-single-character.html
# I want the user to be able to just hit a key to move to the next file, without
# hitting return.  To make that work, we need unbuffered input ...
def getch():
  fd = sys.stdin.fileno()

  oldterm = termios.tcgetattr(fd)
  newattr = termios.tcgetattr(fd)
  newattr[3] = newattr[3] & ~termios.ICANON & ~termios.ECHO
  termios.tcsetattr(fd, termios.TCSANOW, newattr)

  oldflags = fcntl.fcntl(fd, fcntl.F_GETFL)
  #fcntl.fcntl(fd, fcntl.F_SETFL, oldflags | os.O_NONBLOCK)
  fcntl.fcntl(fd, fcntl.F_SETFL, oldflags)

  try:
    while 1:
      try:
        c = sys.stdin.read(1)
        break
      except IOError: pass
  finally:
    termios.tcsetattr(fd, termios.TCSAFLUSH, oldterm)
    fcntl.fcntl(fd, fcntl.F_SETFL, oldflags)
  return c

fileIterator = os.scandir(regExDir)
print ("Revewing RegEx matches (" + str(len(list(fileIterator))) + " files)")
input ("Hit enter to start")

#recalculate the fileIterator
fileIterator = os.scandir(regExDir)

for file in fileIterator:
    name = file.name

    os.system('less ' + regExDir+name)

    print ("<space> to move " + name + " to \"interesting\", B to view again, Q to quit, any other key to \"ignore\"")
    c = getch()

    if c == 'B':  # bit of a lazy hack, only give one crack at viewing file again
        os.system('less ' + regExDir+name)
        print ("<space> to move " + name + " to \"interesting\", Q to quit, any other key to \"ignore\"")
        c = getch()

    if c == 'Q':
        exit()
    elif c == ' ':
        os.rename(regExDir+name, interestingDir+name)
    else:
        os.rename(regExDir+name, ignoreDir+name)
