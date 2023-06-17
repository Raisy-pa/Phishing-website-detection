import numpy as np
from flask import Flask, render_template, request
from werkzeug.utils import secure_filename
from werkzeug.datastructures import  FileStorage
app = Flask(__name__)
import os
#import fetch
import feature_extracter_imp
#import fetch_url_details
dirname = os.path.dirname(__file__)
import pickle
import fetch_URL_details
#model = pickle.load(open('model_60.pkl', "rb"))
model = pickle.load(open('xgb.pkl', "rb"))
import joblib
#import xgboost as xgb
#model_xgb = xgb.XGBClassifier()
#model = model_xgb.load_model("model_7.sav")
import pandas as pd 
from playsound import playsound


@app.route('/', methods = ['GET','POST'])
def home():
    if request.method == 'POST':
      print(request.form)
      print(request.files)
      print(request)
      #features = ['domain','havingIP','haveAtSign','getLength','getDepth','redirection','httpDomain','tinyURL','prefixSuffix','__get_entropy','special','is_encoded','suspecious_tld','dns,web_traffic','domainAge','domainEnd','PageRank','GoogleIndex','iframe','rightClick','forwarding','label']
      #fetch_url_details.getDomain(request.form['url'])
      result = fetch_URL_details.fetch(request.form['url'])
      #array  =fetch.fetch(request.form['url'])
      #x = []
      #for i in range(len(array)):
          #x.append(array[i][0])
      #df = pd.DataFrame([x], columns =['UsingIp', 'longUrl', 'shortUrl', "'@'symbol", 'redirecting', 'prefixSuffix', 'SubDomains', 'Hppts', 'DomainRegLen', 'Favicon', 'HTTPSDomainURL', 'RequestURL', 'AnchorURL', 'LinksInScriptTags', 'ServerFormHandler', 'InfoEmail', 'WebsiteForwarding', 'DisableRightClick', 'UsingPopupWindow', 'IframeRedirection', 'AgeofDomain', 'WebsiteTraffic', 'PageRank', 'GoogleIndex', 'LinksPointingToPage', 'special', 'getDept', 'is_encoded', '__get_entropy', 'suspecious_tld'])
      
      x= feature_extracter_imp.fetch88(request.form['url'])
      print(x)
      if len(x) ==0:
        return render_template('phishing_home.html',status ='Fail' )
      x =[x]
      x = np.array(x)
      phishing = model.predict(x)[0]
      playsound('text.mp3')
      #y_pro_phishing = model.predict_proba(df)[0,0]
      #y_pro_non_phishing = model.predict_proba(df)[0,1]
      #print(y_pro_phishing)
      #print(y_pro_non_phishing)
      return render_template('result.html',result =result,phishing=phishing)

    else:
      return render_template('phishing_home.html',status ='' )


if __name__ == '__main__':
   app.run(debug = True)