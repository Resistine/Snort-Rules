import sys
import os

# Add parent directory to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))

from snortparser import Parser

rule = 'alert tcp $HOME_NET 2589 -> $EXTERNAL_NET any (msg:"MALWARE-BACKDOOR - Dagger_1.4.0"; reference:nessus,11157; classtype:misc-activity; sid:105; rev:1;)'
parsed = Parser(rule)

print("Msg:", parsed.options['msg'])
print("Reference:", parsed.options['reference'])
