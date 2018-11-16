import subprocess
import shlex
from time import sleep

sleep(10)

cmd='dig +dnssec any feec.vutbr.cz +tcp'
proc=subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
proc.communicate()

cmd='dig +dnssec any fit.vutbr.cz +tcp'
proc=subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
proc.communicate()

cmd='dig +dnssec any facebook.com +tcp'
proc=subprocess.Popen(shlex.split(cmd),stdout=subprocess.PIPE)
proc.communicate()