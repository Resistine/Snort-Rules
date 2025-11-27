#!/usr/bin/env python3
# Copyright (c) 2024 Resistine

import sys
import traceback
import os.path
import urllib.request
import tarfile
import pandas as pd
import ast

from snortparser.snortparser import Parser, Dicts
import mitreattack.attackToExcel.attackToExcel as attackToExcel

# Constants
INBOUND = 'inb'
LATERAL = 'lat'
OUTBOUND = 'out'

# Output file
CSVFILE = "rules_parsed.csv"
COLUMNS = ['sid', 'proto', 'source', 'src_port', 'arrow', 'destination', 'dst_port', 'classtype', 
           'direction',	'TActic', 'Technique', 'Tname', 'TA_inb', 'T_inb',  'TA_lat', 'T_lat', 'TA_out', 'T_out',
           'msg', 'reference']

# Snort rules file and URL
TARFILE = "snort3-community-rules.tar.gz"
LINK = "https://www.snort.org/downloads/community/"+ TARFILE
DIR = "snort3-community-rules"
FILE = "snort3-community.rules"
RULES = os.path.join(DIR, FILE)

# ProofPoint Emerging Threats Open Ruleset
ET_FILE = "emerging.rules"
ET_LINK = "https://rules.emergingthreats.net/open/suricata-7.0.3/emerging.rules.zip"
ET_DIR = "et-open-rules"
ET_RULES = os.path.join(ET_DIR, ET_FILE)



# MITRE ATT&CK files
MAPPINGS = "mappings.csv"
ATTACK_DIR = "enterprise-attack"
TACTICS = "enterprise-attack-tactics.xlsx"
ATTACK_TAs = os.path.join(ATTACK_DIR, TACTICS)
TECHNIQUES = "enterprise-attack-techniques.xlsx"
ATTACK_Tes = os.path.join(ATTACK_DIR, TECHNIQUES)

# download the MITRE ATT&CK and create the Excel files if they do not exist
if (not os.path.exists(ATTACK_DIR)):
    try:
        attackToExcel.export("enterprise-attack")
    except Exception as e:
        print("Exception while downloading MITRE ATT&CK: "+ str(e))
        exit(1)

# read the MITRE ATT&CK TActics and Techniques into DataFrames
TAs = pd.read_excel(ATTACK_TAs, dtype=str)
Tes = pd.read_excel(ATTACK_Tes, dtype=str)


# read the Resistine Snort to MITRE ATT&CK TActics mappings or exit if the file was deleted
if (not os.path.exists(MAPPINGS)):
    print("There is no "+ MAPPINGS +" file in the current directory.")
    print("Please, get the mappings file from Git or the shared Drive and try again.")
    exit(1)

df_mappings = pd.read_csv(MAPPINGS, dtype=str)
# print(df_mappings) # DEBUG: print the NaNs in the DataFrame

# Helper function to get the TActic for the classtype and direction from the mappings file.
def get_TActic(classtype, column):
    '''Get the TActic for the classtype and direction from the mappings file.'''
    
    # get the TActic for the classtype a the proper direction from the mappings file
    try:
        d = df_mappings.loc[df_mappings['classtype'] == classtype, column].iloc[0]
        # fix the NaN and \xa0 BSs in the DataFrame ... 
        if (pd.isna(d)): d = None
    except IndexError:
        print("No record for the classtype: "+ classtype)
        return None  # or any default value
    
    # if d is already defined, then return it or get the default TActic from the mappings
    if (d): return d
    else:
        d = df_mappings.loc[df_mappings['classtype'] == classtype, "TActic"].iloc[0]
        if (pd.isna(d)): d = None
    
    return d



# download the Snort rules if they do not exist
if (not os.path.exists(RULES)):
    try:
        if (not os.path.isdir(DIR)): os.makedirs(DIR)
        urllib.request.urlretrieve(LINK, os.path.join(DIR, TARFILE))
        
        tar = tarfile.open(os.path.join(DIR, TARFILE), "r:gz")
        tar.extractall()
        tar.close()

    except Exception as e:
        print("Exception while downloading Snort rules: "+ str(e))



# Helper function to get the connection/attack direction (inbound/outbound) from the parsed rule and return it.
def get_direction(source, arrow, destination):
    '''Get the connection/attack direction from the parsed rule and return it.
       This is a best effort function as the direction depends on the newtwork topology and the actual flow,
       ie> any, $EXTERNAL_NET, $HOME_NET, ... IP/CIDR, [groups], '!...', etc.
       @see: https://docs.snort.org/rules/headers/directions and https://docs.snort.org/rules/headers/ips 
       @see: https://docs.suricata.io/en/latest/rules/intro.html
    '''
    # not sure about undefined as the snortparser does not allow it (see https://github.com/g-rd/snortparser/issues/5)
    if (not source or not arrow):
        return None

    # FIXME: add more cases for the source and destination
    if (arrow == '->'):
        if (source.startswith('$EXTERNAL_NET')):
            return INBOUND
        if (destination):  # I mean, this should be there always
            if (destination.startswith('$EXTERNAL_NET')):
                return OUTBOUND
            elif (not destination.startswith('any') and not source.startswith('$HOME_NET')):
                return INBOUND
            
    return None



# Helper function to get the first option that starts with the string from the parsed rule and return it.
def get_option(parsed, string):
    '''Get the first option that starts with the string from the parsed rule and return it.'''
    for n in parsed.options:
        if parsed.options[n][0].startswith(string):
            return parsed.options[n]
    return None


# open output file for writing, not appending and write the header ...
with open(CSVFILE, 'w') as csv_rules:
    csv_rules.write(','.join(COLUMNS) + '\n')

    # open input file
    with open(RULES) as snort_rules:
        
        # for each line (rule)
        for rule in snort_rules:
           
            # try to parse the rule
            try:
                parsed = Parser(rule)      
                
                # Create a DataFrame with a single row of the parsed data
                # TODO: convert proper to string https://stackoverflow.com/questions/22005911/convert-columns-to-string-in-pandas#62978895
                df = pd.DataFrame([[
                    get_option(parsed, 'sid')[1][0],
                    parsed.header['proto'],
                    parsed.header['source'][1] if parsed.header['source'] else pd.NA,
                    parsed.header['src_port'][1] if parsed.header['src_port'] else pd.NA,
                    parsed.header['arrow'],
                    parsed.header['destination'][1] if parsed.header['destination'] else pd.NA,
                    parsed.header['dst_port'][1] if parsed.header['dst_port'] else pd.NA,
                    get_option(parsed, 'classtype')[1][0],
                    pd.NA, # 'inbound' or 'outbound'
                    pd.NA, # 'TActic' -- this is the most important to be added
                    pd.NA, # 'Technique' -- this is the second most important to be added
                    pd.NA, # 'Tname' -- the Technique name from MITRE ATT&CK Excel file
                    pd.NA, # 'TA_inb' -- inbounds TActic
                    pd.NA, # 'T_inb' -- inbounds Technique (black magic here!)
                    pd.NA, # 'TA_lat' -- lateral TActic
                    pd.NA, # 'T_lat' -- lateral Technique (black magic here!)
                    pd.NA, # 'TA_out' -- outbounds TActic
                    pd.NA, # 'T_out' -- outbounds Technique (black magic here!)
                    get_option(parsed, 'msg')[1][0],
                    get_option(parsed, 'reference')[1] if get_option(parsed, 'reference') else pd.NA
                ]], columns=COLUMNS, dtype=str)
                
                # add the inbound/outbound directions
                # TODO: add some check after the Snort rule header is malformed ['alert', 'ssl'] is fixed
                direction = get_direction(df['source'][0], df['arrow'][0], df['destination'][0])
                df['direction'] = direction

                # switch TActics -- first the specific one, then the generic one
                classtype = df['classtype'][0]
                if (direction == INBOUND):
                    df['TActic'] = df['TA_inb'] = get_TActic(classtype, 'TA_inb')
                elif (direction == LATERAL):
                    df['TActic'] = df['TA_lat'] = get_TActic(classtype, 'TA_lat')
                elif (direction == OUTBOUND):
                    df['TActic'] = df['TA_out'] = get_TActic(classtype, 'TA_out')
                else: # if the direction is not defined, then try to get the default TActic from the mappings
                    df['TActic'] = get_TActic(classtype, 'TActic')

                # finally, add and check the Techniques present as string ['url', 'attack.mitre.org/techniques/T1014']
                if (pd.notna(df['reference'][0])):
                    list_from_string = ast.literal_eval(df['reference'][0])
                    s = pd.Series(list_from_string)

                    # Create a mask for items that start with the specified string
                    mask = s.str.startswith('attack.mitre.org/techniques/')
                    # remove the elements that don't match the mask
                    s = s[mask]

                    # remove the specified string from the start of the strings
                    if (len(s) > 0):
                        s[mask] = s[mask].str.replace('attack.mitre.org/techniques/', '', n=1)
                        # get just the elements that match the mask and its name from the MITRE ATT&CK Excel file
                        df['Technique'] = s[1]
                        
                        # Safe lookup for Tname
                        tname_lookup = Tes.loc[Tes['ID'] == s[1], "name"]
                        if not tname_lookup.empty:
                            df['Tname'] = tname_lookup.iloc[0]
                        else:
                            print(f"Warning: Technique ID {s[1]} not found in MITRE ATT&CK data.")

                # print the Pandas DataFrame to the output file
                csv_rules.write(df.to_csv(index=False, header=False))
                # print(df)

            # NOTE: If the snortparser is unable to parse the rule, it will return a ValueError with the invalid rule item.
            except Exception as e:
                print("Exception: "+ str(e))
                print(traceback.format_exc())
                print(rule)

# Hooraay! We are done
print('There you are: '+ CSVFILE)
