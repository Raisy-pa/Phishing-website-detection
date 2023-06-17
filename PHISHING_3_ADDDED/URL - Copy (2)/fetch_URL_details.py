from  math import log
import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse

class FeatureExtractionFinal:
    features = []
    def __init__(self,url):
        self.features = []
        self.url = url
        self.domain = ""
        self.whois_response = ""
        self.urlparse = ""
        self.response = ""
        self.soup = ""
        self._404_ = "No"

        def Request(self):
          try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
            self.features.append(['URL',url,""])
            self.features.append(['Http Response',str(self.response),"An HTTP response code is a three-digit number that indicates the status of a server's response to a client's request"])
          except Exception as e:
            if (str(e)=="'Timed Out'"):
                self.features.append(['Http Response','Timed Out',"An HTTP response code is a three-digit number that indicates the status of a server's response to a client's request"])
            else:
              self.features.append(['Http Response'+str(self.response ),"An HTTP response code is a three-digit number that indicates the status of a server's response to a client's request"])
        Request(self)
        try:
            self.urlparse = urlparse(self.url)
            self.domain = self.urlparse.netloc
            self.features.append(['Domain Name',str(self.domain),'A domain name is the unique name that identifies an internet resource, such as a website. It is the part of a URL (Uniform Resource Locator) that comes after the "http://" or "https://" and before the first "/".'])
        except Exception as e:
            self.features.append(['Domain Name','Not Foud','A domain name is the unique name that identifies an internet resource, such as a website. It is the part of a URL (Uniform Resource Locator) that comes after the "http://" or "https://" and before the first "/".'])

        try:
            self.whois_response = whois.whois(self.domain)

        except Exception as e:
            pass

        
        self.features.append(self.UsingIp())
        self.features.append(self.longUrl())
        self.features.append(self.shortUrl())
        self.features.append(self.symbol())
        self.features.append(self.redirecting())
        self.features.append(self.prefixSuffix())
        self.features.append(self.SubDomains())
        self.features.append(self.Hppts())
        self.features.append(self.DomainCre())
        self.features.append(self.DomainExp())
        self.features.append(self.Favicon())
        
        self.features.append(self.RequestURL())
        self.features.append(self.AnchorURL())



        self.features.append(self.DisableRightClick())
        self.features.append(self.UsingPopupWindow())
        self.features.append(self.AgeofDomain())
        #self.features.append(self.WebsiteTraffic())
        self.features.append(self.PageRank())
        #added
        self.features.append(self.special())
        self.features.append(self.is_encoded())
        self.features.append(self.__get_entropy())



     # 1.UsingIp
    def UsingIp(self):
        try:
            ipaddress.ip_address(self.url)
            return ['Ipv4 or Ipv6 address?','Yes','Checks for the presence of IP address in the URL. URLs may have IP address instead of domain name. If an IP address is used as an alternative of the domain name in the URL, we can be sure that someone is trying to steal personal information with this URL.']
        except:
            return ['Ipv4 or Ipv6 address?','No','Checks for the presence of IP address in the URL. URLs may have IP address instead of domain name. If an IP address is used as an alternative of the domain name in the URL, we can be sure that someone is trying to steal personal information with this URL.']

    # 2.longUrl
    def longUrl(self):

        return ['Length of URL',str(len(self.url)),'Phishers can use long URL to hide the doubtful part in the address bar']

    # 3.shortUrl
    def shortUrl(self):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                    'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                    'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                    'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                    'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                    'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                    'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', self.url)
        if match:
            return ['is the URL is shortUrl?','Yes','URL shortening is a method on the “World Wide Web” in which a URL may be made considerably smaller in length and still lead to the required webpage. This is accomplished by means of an “HTTP Redirect” on a domain name that is short, which links to the webpage that has a long URL.']
        return ['is the URL is shortUrl?','No','URL shortening is a method on the “World Wide Web” in which a URL may be made considerably smaller in length and still lead to the required webpage. This is accomplished by means of an “HTTP Redirect” on a domain name that is short, which links to the webpage that has a long URL.']

    # 4.Symbol@
    def symbol(self):
        if re.findall("@",self.url):
            return ['@ Symbol Present in URL?','Yes','Using “@” symbol in the URL leads the browser to ignore everything preceding the “@” symbol and the real address often follows the “@” symbol.']
        return ['@ Symbol Present in URL?','No','Using “@” symbol in the URL leads the browser to ignore everything preceding the “@” symbol and the real address often follows the “@” symbol.']
    
    # 5.Redirecting//
    def redirecting(self):
        if self.url.rfind('//')>6:
            return [' Redirection "//" in URL','Yes','he existence of “//” within the URL path means that the user will be redirected to another website. The location of the “//” in URL is computed. We find that if the URL starts with “HTTP”, that means the “//” should appear in the sixth position. However, if the URL employs “HTTPS” then the “//” should appear in seventh position.']
        return [' Redirection "//" in URL','No','he existence of “//” within the URL path means that the user will be redirected to another website. The location of the “//” in URL is computed. We find that if the URL starts with “HTTP”, that means the “//” should appear in the sixth position. However, if the URL employs “HTTPS” then the “//” should appear in seventh position']
    
    # 6.prefixSuffix
    def prefixSuffix(self):
        try:
            match = re.findall('\-', self.domain)
            if match:
                return ['Prefix or Suffix "-" in Domain','Yes','The dash symbol is rarely used in legitimate URLs. Phishers tend to add prefixes or suffixes separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage.']
            return ['Prefix or Suffix "-" in Domain','No','The dash symbol is rarely used in legitimate URLs. Phishers tend to add prefixes or suffixes separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage.']
        except:
            return['Prefix or Suffix "-" in Domain','Exception','The dash symbol is rarely used in legitimate URLs. Phishers tend to add prefixes or suffixes separated by (-) to the domain name so that users feel that they are dealing with a legitimate webpage.']
    
    # 7.SubDomains
    def SubDomains(self):
        dot_count = len(re.findall("\.", self.url))
        if dot_count == 1:
            return ['Number of Subdomains',str(dot_count),'A subdomain is an additional directory or location of a website that is typically used to distinguish content types or the type of information presented with each subdomain']
        elif dot_count == 2:
            return ['Number of Subdomains',str(dot_count),'A subdomain is an additional directory or location of a website that is typically used to distinguish content types or the type of information presented with each subdomain']
        return ['Number of Subdomains',str(dot_count),'A subdomain is an additional directory or location of a website that is typically used to distinguish content types or the type of information presented with each subdomain']

    # 8.HTTPS
    def Hppts(self):
        try:
            https = self.urlparse.scheme
            if 'https' in https:
                return ['"http/https" in Domain name','Yes','Checks for the presence of "http/https" in the domain part of the URL. The phishers may add the “HTTPS” token to the domain part of a URL in order to trick users.']
            return ['"http/https" in Domain name','No','Checks for the presence of "http/https" in the domain part of the URL. The phishers may add the “HTTPS” token to the domain part of a URL in order to trick users.']
        except:
            return ['"http/https" in Domain name','Exception','Checks for the presence of "http/https" in the domain part of the URL. The phishers may add the “HTTPS” token to the domain part of a URL in order to trick users.']




    # 10. Favicon
    def Favicon(self):
        try:
            for head in self.soup.find_all('head'):
                for head.link in self.soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if self.url in head.link['href'] or len(dots) == 1 or self.domain in head.link['href']:
                        return ['Favicon Present?','Yes','A favicon, also known as a shortcut icon, website icon, tab icon, URL icon, or bookmark icon, is a file containing one or more small icons, associated with a particular website or web page']
            return ['Favicon Present?','No','A favicon, also known as a shortcut icon, website icon, tab icon, URL icon, or bookmark icon, is a file containing one or more small icons, associated with a particular website or web page']
        except:
            return ['Favicon Present?','No','A favicon, also known as a shortcut icon, website icon, tab icon, URL icon, or bookmark icon, is a file containing one or more small icons, associated with a particular website or web page']


    
    # 13. RequestURL#IMP
    def RequestURL(self):
        try:
            success =0
            i=1
            for img in self.soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if self.url in img['src'] or self.domain in img['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for audio in self.soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if self.url in audio['src'] or self.domain in audio['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for embed in self.soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if self.url in embed['src'] or self.domain in embed['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1

            for iframe in self.soup.find_all('iframe', src=True):
                dots = [x.start(0) for x in re.finditer('\.', iframe['src'])]
                if self.url in iframe['src'] or self.domain in iframe['src'] or len(dots) == 1:
                    success = success + 1
                i = i+1
            return ['Total Iframe+audio+img tags count',i,'']
        except:
            return ['Total Iframe+audio+img tags count','Exception','']
    
    # 14. AnchorURL#imp
    def AnchorURL(self):

        try:
            i,unsafe = 0,0
            for a in self.soup.find_all('a', href=True):
                if "#" in a['href'] or "javascript" in a['href'].lower() or "mailto" in a['href'].lower() or not (self.url in a['href'] or self.domain in a['href']):
                    unsafe = unsafe + 1
                i = i + 1
            return ['Total Anchor "a" tags and Number of Unsafe Anchor Tags',str(i)+' and '+str(unsafe),'The <a> tag defines a hyperlink, which is used to link from one page to another.']

        except:
            return  ['Total Anchor "a" tags','Exception','The <a> tag defines a hyperlink, which is used to link from one page to another.']
    
 



    # 21. DisableRightClick
    def DisableRightClick(self):
        try:
            if re.findall(r"event.button ?== ?2", self.response.text):
                return ['RightClick Disabled?','Yes','Phishers use JavaScript to disable the right-click function, so that users cannot view and save the webpage source code. This feature is treated exactly as “Using onMouseOver to hide the Link”. Nonetheless, for this feature, we will search for event “event.button==2” in the webpage source code and check if the right click is disabled.']
            else:
                return ['RightClick Disabled?','No','Phishers use JavaScript to disable the right-click function, so that users cannot view and save the webpage source code. This feature is treated exactly as “Using onMouseOver to hide the Link”. Nonetheless, for this feature, we will search for event “event.button==2” in the webpage source code and check if the right click is disabled.']
        except:
             return ['RightClick Disabled?','Exception','Phishers use JavaScript to disable the right-click function, so that users cannot view and save the webpage source code. This feature is treated exactly as “Using onMouseOver to hide the Link”. Nonetheless, for this feature, we will search for event “event.button==2” in the webpage source code and check if the right click is disabled.']

    # 22. UsingPopupWindow
    def UsingPopupWindow(self):
        try:
            if re.findall(r"alert\(", self.response.text):
                return ['PopUp Window?','Yes','']
            else:
                return ['PopUp Window?','No','']
        except:
             return ['PopUp Window?','Exception','']

    def DomainExp(self):
        try:
            expiration_date = self.whois_response.expiration_date
            try:
                if(len(expiration_date)):
                    expiration_date = expiration_date[0]
            except:
                 return ['Domain Expiration Date',expiration_date.year ,'']
            else:
                return ['Domain Expiration Date',expiration_date ,'']
        except:
            return ['Domain Expiration Date','Exception', '']
    def DomainCre(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                 return ['Domain Expiration Date',creation_date.year ,'']
            else:   
               return ['Domain Creation Date',creation_date , '']
        except:
            return ['Domain Creation Date','Exception' , '']


    # 24. AgeofDomain
    def AgeofDomain(self):
        try:
            creation_date = self.whois_response.creation_date
            try:
                if(len(creation_date)):
                    creation_date = creation_date[0]
            except:
                pass
            today  = date.today()
            age = (today.year-creation_date.year)*12+(today.month-creation_date.month)
            if age >=6:
                return ['Domain Age(in months)',str(age),'Extracted from WHOIS database. Most phishing websites live for a short period of time. The minimum age of the legitimate domain is considered to be 12 months for this project. Age here is nothing but different between creation and expiration time.']
            return['Domain Age(in months)'+str(age),'Extracted from WHOIS database. Most phishing websites live for a short period of time. The minimum age of the legitimate domain is considered to be 12 months for this project. Age here is nothing but different between creation and expiration time.']
        except:
            return ['Domain Age(in months)','Exception','Extracted from WHOIS database. Most phishing websites live for a short period of time. The minimum age of the legitimate domain is considered to be 12 months for this project. Age here is nothing but different between creation and expiration time.']

    # 26. WebsiteTraffic   
    def WebsiteTraffic(self):
        try:#exception is normal
            rank = BeautifulSoup(urllib.request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + self.url).read(), "xml").find("REACH")['RANK']
            return ['Alexa Rank',str(rank),"The Alexa rank is a measure of a website's popularity, with a lower rank indicating a higher level of traffic."]
        except :
            return ['Alexa Rank', 'Exception',"The Alexa rank is a measure of a website's popularity, with a lower rank indicating a higher level of traffic."]

    # 27. PageRank--NEW ALGO
    def PageRank(self):
        key = 'cos8sso8g0oogk0gw048gooskkksgskko4kk0o44'
        url = 'https://openpagerank.com/api/v1.0/getPageRank?domains%5B0%5D=' + self.domain 
        try:
            request = requests.get(url, headers={'API-OPR':key})
            result = request.json()
            result = result['response'][0]['page_rank_integer']
            print(result)
            return ['Page Rank',str(result),"PageRank is a method used by Google Search to rank websites in their search engine results."]
        except:
            return ['Page Rank:','Exception',"PageRank is a method used by Google Search to rank websites in their search engine results."]
    def getFeaturesList(self):
        return self.features

    def special(self):
        specialChars = len(self.url) - len( re.findall('[\w]',self.url) )
        return  ['Number of Special Charecters in the String',str(specialChars),"Attackers use special characters for URL encoded attacks to bypass validation logic. We count the number of special characters ;, +=, _, ?, =, &, [ etc.. found in a URL."]

    def is_encoded(self):
        if('%' in self.url.lower()):
          return ['URL Encoded','Yes',"URL encoding can be used to conceal the true destination of a link in a phishing website. By encoding the link to the actual phishing website, the URL may appear to be legitimate, tricking users into visiting the site."]
        return ['URL Encoded','No',"URL encoding can be used to conceal the true destination of a link in a phishing website. By encoding the link to the actual phishing website, the URL may appear to be legitimate, tricking users into visiting the site."]
    def __get_entropy(self):
            url = self.url.lower()
            probs = [url.count(c) / len(url) for c in set(url)]
            entropy = -sum([p * log(p) / log(2.0) for p in probs])
            return ['Entropy of URL',str(entropy),"The entropy of a string or URL is nothing but a measurement of randomness. It will provide us the entropy score of that string, entropy score and randomness is directly proportional to each other. That means the more random a string is, the higher its calculation of randomness. Legitimate domains tend to have well-defined names that speak to a brand or a product so tend to be less disorganized. Thus, measuring the entropy of URL strings tells us which domain names are ‘not-so-real."]

def fetch(url):
    f= FeatureExtractionFinal(url)
    print(f)
    #print(f.DomainCre())
    return f.features

#fetch('https://www.w3schools.com/')