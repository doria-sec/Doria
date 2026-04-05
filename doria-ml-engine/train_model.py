import pandas as pd
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report
from xgboost import XGBClassifier

def train_model_1():
    print("--- Training Model 1: Metadata & Behavior ---")
    df1 = pd.read_csv('model1_features.csv')
    
    X1 = df1.drop(columns=['label'])
    y1 = df1['label']
    X_train1, X_test1, y_train1, y_test1 = train_test_split(X1, y1, test_size=0.2, random_state=42)
    
    model1 = XGBClassifier()
    model1.fit(X_train1, y_train1)
    
    predictions1 = model1.predict(X_test1)
    
    print(classification_report(y_test1, predictions1, target_names=["Safe (0)", "Poisoned (1)"]))
    
    model1.save_model('model1_behavior.json')
    print("Model 1 saved successfully to 'model1_behavior.json'.\n")


def train_model_2():
    print("--- Training Model 2: NLP & Name Risk ---")
    df2 = pd.read_csv('model2_features.csv')
    
    X2 = df2.drop(columns=['label'])
    y2 = df2['label']
    X_train2, X_test2, y_train2, y_test2 = train_test_split(X2, y2, test_size=0.2, random_state=42)
    
    model2 = XGBClassifier()
    model2.fit(X_train2, y_train2)
    
    predictions2 = model2.predict(X_test2)
    print(classification_report(y_test2, predictions2, target_names=["Safe (0)", "Poisoned (1)"]))
    
    model2.save_model('model2_nlp.json')
    print("Model 2 saved successfully to 'model2_nlp.json'.\n")

if __name__ == "__main__":
    train_model_1()
    train_model_2()