#!venv/bin/python
# -*- coding: utf-8 -*-

# TODO Exclude a column when training for a label column

import os
import sys
import warnings

# To perform operations on dataset
import pandas as pd
import numpy as np

# Machine learning model
from sklearn.model_selection import train_test_split
from sklearn.tree import DecisionTreeClassifier

# Visualization
from sklearn import metrics
from sklearn.metrics import confusion_matrix
import matplotlib.pyplot as plt
import seaborn as sns
from sklearn.tree import export_graphviz

# My additions
from ucimlrepo import fetch_ucirepo
from sklearn.linear_model import LinearRegression
import pickle

import argparse

from terminaltexteffects.effects.effect_print import Print

warnings.filterwarnings("ignore")

parser = argparse.ArgumentParser(
                    prog='analyze_url',
                    description='Analyze a URL for debugging the Phish Hunter ML AI')

parser.add_argument('-d', '--dataset')      # dataset for training the ai model # 'new_dataset.csv'
parser.add_argument('-o', '--dot')          # dot file  #'tree.dot'
parser.add_argument('-m', '--matrix')      # confusion matrix  #'confusion_matrix.png'
parser.add_argument('-nb', '--no_banner', action='store_true')

args = parser.parse_args()

if not args.no_banner:
    effect = Print("""
\\_____)\\_____
 /--v____ __`<  Phish Hunter Artifical Intelligence version 1.00        
         )/     Training Phish Hunter  
         '
            """)
    with effect.terminal_output() as terminal:
        for frame in effect:
            terminal.print(frame)

if args.dataset is None:
    parser.print_help()
    sys.exit(1)

if args.dot is None:
    parser.print_help()
    sys.exit(1)

if args.matrix is None:
    parser.print_help()
    sys.exit(1)

print("[+] Staring Phish Hunter AI Training Mode...")

print("[+] Loading the dataset...")
df = pd.read_csv(args.dataset) 
dot_file = args.dot
confusion_matrix_file = args.matrix

X = df.iloc[:, :-1]
y = df.iloc[:, -1]

print("[+] Splitting data into Train and Test data...")
Xtrain, Xtest, ytrain, ytest = train_test_split(X, y, random_state=0)

print("[+] Creating Model Decision Tree Classifier...")
model = DecisionTreeClassifier()
print("[+] Fitting data and training the Model...")
model.fit(Xtrain, ytrain)

print("[+] Making predictions with Xtest...\n")
ypred = model.predict(Xtest)
print(metrics.classification_report(ypred, ytest))
print("Accuracy Score:", round(metrics.accuracy_score(ytest, ypred), 2)*100, "%")

print("\n[+] Saving Confusion Matrix...")
mat = confusion_matrix(ytest, ypred)
sns.heatmap(mat.T, square=True, annot=True, fmt='d', cbar=False)
plt.xlabel('true label')
plt.ylabel('predicted label')
plt.savefig(confusion_matrix_file)

print("[+] Saving dot file...")
export_graphviz(model, out_file=dot_file, feature_names=X.columns.values)

print("[+] Converting dot file to image...")
os.system("dot -Tpng tree.dot -o tree.png")

# Save the model to a file
print("[+] Saving the model to file for later use...")
with open('decision_tree_model.pkl', 'wb') as file:
    pickle.dump(model, file)

print("[+] DONE!\n")
