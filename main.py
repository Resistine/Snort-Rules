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
#given row, have to look at all tactic columns, return list of non empty unique tactics
def combTactics(row):
    tactics=[]
    






