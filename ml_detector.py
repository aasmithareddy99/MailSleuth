"""Optional scikit-learn model. Dataset is synthetic and is for demonstration, not production claims."""
from pathlib import Path
import csv, json
ROOT=Path(__file__).resolve().parent
DATA=ROOT/'data'/'labeled_emails.csv'
MODEL=ROOT/'data'/'phishing_model.joblib'


def get_ml_status():
    try:
        import sklearn
        installed=True; version=sklearn.__version__
    except Exception:
        installed=False; version=None
    return {'available': installed and MODEL.exists(), 'sklearn_installed':installed,'sklearn_version':version,'model_file_exists':MODEL.exists(),
            'dataset':str(DATA.relative_to(ROOT)),'dataset_note':'Bundled examples are synthetic; use a representative, consented, labeled dataset before making performance claims.'}

def load_rows():
    with DATA.open(encoding='utf-8',newline='') as f:
        rows=list(csv.DictReader(f))
    return rows

def train_and_evaluate():
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import LogisticRegression
    from sklearn.pipeline import Pipeline
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
    import joblib
    rows=load_rows()
    texts=[(r['sender']+' '+r['subject']+' '+r['body']).strip() for r in rows]
    labels=[int(r['label']) for r in rows]
    if len(rows)<20 or len(set(labels))<2: raise ValueError('Need at least 20 labeled examples and both classes.')
    X_train,X_test,y_train,y_test=train_test_split(texts,labels,test_size=0.25,random_state=42,stratify=labels)
    model=Pipeline([('tfidf',TfidfVectorizer(ngram_range=(1,2),max_features=12000,strip_accents='unicode',sublinear_tf=True)),('classifier',LogisticRegression(max_iter=1000,class_weight='balanced',random_state=42))])
    model.fit(X_train,y_train); pred=model.predict(X_test)
    joblib.dump(model,MODEL)
    cm=confusion_matrix(y_test,pred,labels=[0,1]).tolist()
    return {'available':True,'model':'TF-IDF + Logistic Regression','dataset_size':len(rows),'train_size':len(X_train),'test_size':len(X_test),
      'metrics':{'accuracy':round(accuracy_score(y_test,pred),4),'precision':round(precision_score(y_test,pred,zero_division=0),4),
      'recall':round(recall_score(y_test,pred,zero_division=0),4),'f1':round(f1_score(y_test,pred,zero_division=0),4),
      'confusion_matrix_labels':['legitimate','phishing'],'confusion_matrix':cm,
      'classification_report':classification_report(y_test,pred,target_names=['legitimate','phishing'],zero_division=0,output_dict=True)},
      'caveat':'Metrics are on a small synthetic dataset and must not be represented as real-world performance.'}

def predict_ml(sender: str, subject: str, body: str):
    try:
        import joblib
        if not MODEL.exists(): return {'available':False,'reason':'Model not trained yet. Use POST /api/ml/evaluate to train and evaluate it.'}
        model=joblib.load(MODEL)
        text=f'{sender} {subject} {body}'
        probs=model.predict_proba([text])[0]
        classes=list(model.named_steps['classifier'].classes_)
        phishing_idx=classes.index(1) if 1 in classes else 0
        p=float(probs[phishing_idx])
        return {'available':True,'model':'TF-IDF + Logistic Regression','phishing_probability':round(p,4),'predicted_label':'phishing' if p>=0.5 else 'legitimate','dataset_note':'Trained on bundled synthetic examples; do not use as sole decision signal.'}
    except Exception as exc: return {'available':False,'reason':type(exc).__name__}
