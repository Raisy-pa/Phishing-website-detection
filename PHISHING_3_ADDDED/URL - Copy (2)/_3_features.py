from  math import log
import re
import urllib.request
import requests
import pandas as pd
import csv


def special(url):
        specialChars = len(url) - len( re.findall('[\w]',url) )
        return  specialChars
def is_encoded(url):
        if('%' in url.lower()):
          return 1
        return 0
def __get_entropy(url):
            probs = [url.count(c) / len(url) for c in set(url)]
            entropy = -sum([p * log(p) / log(2.0) for p in probs])
            return entropy

def fetch(url):  
    featueres3 = []
    featueres3.append(special(url))
    featueres3.append(is_encoded(url))
    featueres3.append(__get_entropy(url))
    return  featueres3