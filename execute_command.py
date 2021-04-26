#!/usr/bin/env python

import subprocess

#executing win command via python on win10, test

command = "msg * hello world"
subprocess.Popen(command, shell=True)