#importing librarys needed for right now
import pandas as pd
from sklearn.model_selection import train_test_split
import os

#read csv file into pandas df
df = pd.read_csv("mappings.csv")
print("loaded dataset")
print(df.head())

#start basic cleaning


