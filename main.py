#importing librarys needed for right now
import pandas as pd
from sklearn.model_selection import train_test_split
import os

#IMPORT DATA
#read csv file into pandas df
df = pd.read_csv("mappings.csv")
print("loaded dataset")
print(df.head())

#START BASIC CLEANING
#replace Na values with empty strings
df = df.fillna("")
print("post cleaning")
print(df.head())

#COMBINE TACTICS INTO A COLUMN
tacticColumns= ["TActic", "TA_inb", "TA_lat", "TA_out"]
#for each row, put all the tactics into a list and output as labels
def combTactics(row):
    tactics=[] #create empty row
    for col in tacticColumns:
        value = row[col]
        if isinstance(value, str) and value.strip()!= "" :
            tactics.append(value.strip())
    return list(set(tactics)) #remove duplicates

df["Labels"]= df.apply(combTactics, axis = 1)
print("Tactics combined into 'Labels' column: ")
print(df[["classtype", "Labels"]].head())


#MAKE SURE EACH ROW HAS AT LEAST 1 LABEL
df = df[df["Labels"].map(len)>0]
print("rows without labels not here, new dataset size is: ", len(df))







