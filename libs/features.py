# Exraction of features from the URL
#  0   having_IP_Address
#  1   URL_Length
#  2   Shortining_Service
#  3   having_At_Symbol
#  4   double_slash_redirecting
#  5   Prefix_Suffix
#  6   having_Sub_Domain
#  7   SSLFinal_State
#  8   Domain_registeration_length
#  9   Favicon
#  10  port
#  11  HTTPS_token
#  12  Request_URL
#  13  URL_of_Anchor
#  14  Links_in_tags
#  15  SFH
#  16  Submitting_to_email
#  17  Abnormal_URL
#  18  Redirect
#  19  on_mouseover
#  20  RightClick
#  21  popUpWidnow
#  22  Iframe
#  23  age_of_domain
#  24  DNSRecord
#  25  web_traffic


# Above fetatures function returns
# 1 if the URL is Phishing,
# -1 if the URL is Legitimate and
# 0 if the URL is Suspicious

import re
import csv
import whois
import datetime
import requests
import ipaddress
from dns import resolver
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urlencode
from thlibs.sslchecker import SSLChecker


class FeatureExtraction:
    def __init__(self, url):
        self.url = url
        self.parsedurl = urlparse(self.url)
        self.domain = self.parsedurl.netloc

        self.user_agent = "Mozilla/5.0 (X11; CrOS x86_64 12871.102.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/81.0.4044.141 Safari/537.36" #'Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/48.0.2564.116 Safari/537.36'
        self.headers = {'User-Agent': self.user_agent}

        self.google_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 6.1; WOW64; rv:49.0) Gecko/20100101 Firefox/49.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1'
        }

        try:
            self.whois = whois.whois(self.domain)
        except:
            self.whois = None

        try:
            self.request = requests.get(self.url, timeout=5, headers=self.headers)
            self.soup = BeautifulSoup(self.request.content, 'html.parser')
        except:
            self.request = None
            self.soup = None

        self.shortening_services = r"bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|" \
            "ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|" \
            r"yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|" \
            r"short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|" \
            r"doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|db\.tt|" \
            r"qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|q\.gs|is\.gd|" \
            r"po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|x\.co|" \
            r"prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|" \
            r"tr\.im|link\.zip\.net"

    def getFeaturesDict(self):
        """
        getFeatureDict

        :return:

        Get the features for a url in the data type of an dict with the feature labels

        """
        return {
            "having_IP_Address": self.having_IP_Address(),
            "URL_Length": self.URL_Length(),
            "Shortining_Service": self.Shortining_Service(),
            "having_At_Symbol": self.having_At_Symbol(),
            "double_slash_redirecting": self.double_slash_redirecting(),
            "Prefix_Suffix": self.Prefix_Suffix(),
            "having_Sub_Domain": self.having_Sub_Domain(),
            "SSLFinal_State": self.SSLFinal_State(),
            "Domain_registeration_length": self.Domain_registeration_length(),
            "Favicon": self.Favicon(),
            "port": self.port(),
            "HTTPS_token": self.HTTPS_token(),
            "Request_URL": self.Request_URL(),
            "URL_of_Anchor": self.URL_of_Anchor(),
            "Links_in_tags": self.Links_in_tags(),
            "SFH": self.SFH(),
            "Submitting_to_email": self.Submitting_to_email(),
            "Abnormal_URL": self.Abnormal_URL(),
            "Redirect": self.Redirect(),
            "on_mouseover": self.on_mouseover(),
            "RightClick": self.RightClick(),
            "popUpWidnow": self.popUpWidnow(),
            "Iframe": self.Iframe(),
            "age_of_domain": self.age_of_domain(),
            "DNSRecord": self.DNSRecord(),
            "web_traffic": self.web_traffic()
        }

    def getFeaturesArray(self):
        """
        getFeaturesArray

        :return:

        Get the features for a url in the data type of an array

        """
        return [
            self.having_IP_Address(),
            self.URL_Length(),
            self.Shortining_Service(),
            self.having_At_Symbol(),
            self.double_slash_redirecting(),
            self.Prefix_Suffix(),
            self.having_Sub_Domain(),
            self.SSLFinal_State(),
            self.Domain_registeration_length(),
            self.Favicon(),
            self.port(),
            self.HTTPS_token(),
            self.Request_URL(),
            self.URL_of_Anchor(),
            self.Links_in_tags(),
            self.SFH(),
            self.Submitting_to_email(),
            self.Abnormal_URL(),
            self.Redirect(),
            self.on_mouseover(),
            self.RightClick(),
            self.popUpWidnow(),
            self.Iframe(),
            self.age_of_domain(),
            self.DNSRecord(),
            self.web_traffic()
        ]

    def getPageSource(self):
        """
        Return the requested URLs source

        :return:

        """
        return self.soup

    def append_dataset(self, filename=None, new_row=None):
        """
        Adds a new row to a CSV file.

        Args:
            filename (str): The name of the CSV file.
            new_row (list): A list representing the new row to add.

        """
        try:
            with open(filename, 'a', newline='\n') as file:
                writer = csv.writer(file)
                writer.writerow(new_row)
        except Exception as e:
            print(f"An error occurred: {e}")

    def having_IP_Address(self):
        """
        having_IP_Address

        :return:

        IP Address in the URL

        Checks for the presence of IP address in the URL. URLs may have IP address instead of domain name.
        If an IP address is used as an alternative of the domain name in the URL, we can be sure that someone is
        trying to steal personal information with this URL.

        If the domain part of URL has IP address, the value assigned to
        this feature is 1 (phishing) or else -1 (legitimate).

        """
        try:
            ipaddress.ip_address(self.domain)
            return 1
        except Exception as err:
            return -1

    def URL_Length(self):
        """
        URL_Length

        :return:

        Computes the length of the URL. Phishers can use long URL to hide the doubtful part in the address bar.
        In this project, if the length of the URL is greater than or equal 54 characters then the URL
        classified as phishing otherwise legitimate.

        If the length of URL >= 54 , the value assigned to this
        feature is 1 (phishing) or else 0 (suspicious) else -1 (legitimate).

        """
        if len(self.url) < 54:
            return -1
        elif len(self.url) >= 54 and len(self.url) <= 75:
            return 0
        else:
            return 1

    def Shortining_Service(self):
        """
        Shortining_Service

        :return:

        Using URL Shortening Services “TinyURL”

        URL shortening is a method on the “World Wide Web” in which a URL may be made considerably
        smaller in length and still lead to the required webpage. This is accomplished by means of an
        “HTTP Redirect” on a domain name that is short, which links to the webpage that has a long URL.

        If the URL is using Shortening Services, the value assigned to this
        feature is 1 (phishing) or else -1 (legitimate).

        """
        if re.search(self.shortening_services, self.url):
            return 1
        else:
            return -1

    def having_At_Symbol(self):
        """
        having_At_Symbol

        :return:

        "@" Symbol in URL

        Checks for the presence of '@' symbol in the URL. Using “@” symbol in the URL leads the browser
        to ignore everything preceding the “@” symbol and the real address often follows the “@” symbol.

        If the URL has '@' symbol, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).

        """
        if '@' in self.url:
            return 1
        else:
            return -1

    def double_slash_redirecting(self):
        """
        double_slash_redirecting

        :return:

        Redirection "//" in URL

        Checks the presence of "//" in the URL. The existence of “//” within the URL path means that
        the user will be redirected to another website. The location of the “//” in URL is computed.

        If the "//" is anywhere in the URL apart from after the protocol, the value assigned to this
        feature is 1 (phishing) or else -1 (legitimate).

        """
        if re.search(r'https?://[^\s]*//', self.url):
            return 1
        else:
            return -1

    def Prefix_Suffix(self):
        """
        Prefix_Suffix

        :return:

        Prefix or Suffix "-" in Domain

        Checking the presence of '-' in the domain part of URL. The dash symbol is rarely used in
        legitimate URLs. Phishers tend to add prefixes or suffixes separated by (-) to the domain name so that
        users feel that they are dealing with a legitimate webpage.

        If the URL has '-' symbol in the domain part of the URL, the value assigned to this
        feature is 1 (phishing) or else -1 (legitimate).

        """
        if '-' in self.domain:
            return 1
        else:
            return -1

    def having_Sub_Domain(self):
        """
        having_Sub_Domain

        :return:

        If the URL has more than 2 subdomains, the value assigned to this
        feature is 1 (phishing) or else 0 (suspicious) else -1 (legitimate).

        """
        count = self.domain.count('.')
        if count <= 2:
            return -1
        elif count > 2 and count <= 3:
            return 0
        else:
            return 1

    def SSLFinal_State(self):
        """
        SSLFinal_State

        :return:

        This is supposed to be based on Issuer and Certificate Age...

        But, in all reality most websites use a free cert that is renewed yearly, so age don't mean shit.

        While we can limit on trusted issuers, for now, we are just checking that SSL
        support is available and that the cert is valid (within the current date range).

        This is intended to be extended upon later.

        TODO : Extend to support age?

        """
        port = 443

        if self.parsedurl.port is not None:
            port = self.parsedurl.port
        else:
            if "http://" in self.url:
                port = 80
            elif "https://" in self.url:
                port = 443

        try:
            sslc = SSLChecker(domain=self.domain, port=port)

            if sslc.verify_has_ssl_certificate(domain=self.domain, port=port) and \
                    sslc.verify_ssl_active(domain=self.domain, port=port):
                return -1
            else:
                return 1
        except Exception as err:
            if port == 80:
                port = 443
            elif port == 443:
                port = 80

            try:
                sslc = SSLChecker(domain=self.domain, port=port)

                if sslc.verify_has_ssl_certificate(domain=self.domain, port=port) and \
                        sslc.verify_ssl_active(domain=self.domain, port=port):
                    return -1
                else:
                    return 1
            except Exception as err:
                # Since we failed on port 80 and 443 we are just going
                # to assume this is Suspicious (0) but rate it as Phish (1)
                # because legitimate websites should not fail on both ports
                return 1

    def URL_Depth(self):
        """
        URL_Depth

        :return:

        Computes the depth of the URL. This feature calculates the number of sub pages
        in the given url based on the '/'.

        The value of feature is a numerical based on the URL.

        This isn't even used in the current dataset.

        TODO : Add this in the next dataset

        """
        depth = 0
        subdirs = self.parsedurl.path.split('/')
        for subdir in subdirs:
            if subdir:
                depth += 1
        return depth

    def Domain_registeration_length(self):
        """
        Domain_registeration_length

        :return:

        End Period of Domain

        This feature can be extracted from WHOIS database. For this feature, the
        remaining domain time is calculated by finding the difference between expiration
        time & current time. The end period considered for the legitimate domain is 6 months or more for this project.

        If end period of domain < 6 months, the value of this feature is 1 (phishing) else -1 (legitimate).

        """
        if self.whois is None:
            return 1

        try:
            if type(self.whois['expiration_date']) is list:
                expiration_date = self.whois['expiration_date'][0]
            else:
                expiration_date = self.whois['expiration_date']

            registration_length = abs(
                (expiration_date - datetime.datetime.now()).days)
            if registration_length / 30 >= 6:
                return -1
            else:
                return 1
        except Exception as err:
            return 1

    def Favicon(self):
        """
        Favicon

        :return:

        Checks for the presence of favicon in the website. The presence of favicon in the
        website can be used as a feature to detect phishing websites.

        If the website has favicon, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).

        """
        try:
            if re.findall(r'favicon', self.soup.text) or \
                    self.soup.find('link', rel='shortcut icon') or \
                    self.soup.find('link', rel='icon'):
                return -1
            else:
                return 1
        except Exception as err:
            return 1

    def port(self):
        """
        port

        :return:

        Non-Standard Port

        Checks for the use of non-standard port. Phishers often use non-standard ports
        in the URL in order to make it look like a legitimate one.

        If the URL uses non-standard port, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).

        """
        if self.parsedurl.port:
            return 1
        else:
            return -1

    def HTTPS_token(self):
        """
        HTTPS_token

        :return:

        "http/https" in Domain name

        Checks for the presence of "http/https" in the domain part of the URL.
        The phishers may add the “HTTPS” token to the domain part of a URL in order to trick users.

        If the URL has "http/https" in the domain part, the value assigned to
        this feature is 1 (phishing) or else -1 (legitimate).

        """
        if 'https' in self.domain:
            return 1
        else:
            return -1

    def Request_URL(self):
        """
        Request_URL

        :return:

        The fine line that distinguishes phishing websites from legitimate ones is how many times a
        website has been redirected. In our dataset, we find that legitimate websites have been redirected one
        time max.

        On the other hand, phishing websites containing this feature have been redirected at least 4 times.

        """
        try:
            if len(self.request.history) <= 1:
                return -1
            elif len(self.request.history) > 1 and len(self.request.history) <= 4: # used to be  NO > 1 and <= 3
                return 0
            else:
                return 1
        except Exception as err:
            return -1

    def URL_of_Anchor(self):
        """
        URL_of_Anchor

        :return:

        The presence of “<a>” HTML tag in the URL is a strong indicator of phishing websites.
        This feature checks for the presence of “<a>” tag in the URL.

        If the URL has “<a>” tag, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).

        """
        try:
            count = 0
            for i in self.soup.find_all('a'):
                if i.has_attr('href'):
                    count += 1
            if count == 0:
                return 1
            else:
                return -1
        except Exception as err:
            return 1

    def Links_in_tags(self):
        """
        Links_in_tags

        :return:

        The presence of “<link>” HTML tag in the URL is a strong indicator of phishing websites.
        This feature checks for the presence of “<link>” tag in the URL.

        If the URL has “<link>” tag, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).

        """
        try:
            count = 0
            for i in self.soup.find_all('link'):
                if i.has_attr('href'):
                    count += 1
            if count == 0:
                return 1
            else:
                return -1
        except Exception as err:
            return 1

    def SFH(self):
        """
        SFH

        :return:


        The presence of “<form>” HTML tag in the URL is a strong indicator of phishing websites.
        This feature checks for the presence of “<form>” tag in the URL.

        If the URL has “<form>” tag, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).

        """
        try:
            if self.soup.find('form'):
                return 1
            else:
                return -1
        except Exception as err:
            return 0

    def Submitting_to_email(self):
        """
        Submitting_to_email

        :return:

        The presence of “mailto:” in the URL is a strong indicator of phishing websites.
        This feature checks for the presence of “mailto:” in the URL.

        If the URL has “mailto:” tag, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).

        """
        try:
            if self.soup.find('mailto:'):
                return 1
            else:
                return -1
        except Exception as err:
            return 0

    """#### ** Abnormal_URL **
    The presence of “<script>” HTML tag in the URL is a strong indicator of phishing websites. This feature checks for the presence of “<script>” tag in the URL.
    If the URL has “<script>” tag, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).
    """

    def Abnormal_URL(self):
        try:
            if re.findall(r'script|javascript|alert|onmouseover|onload|onerror|onclick|onmouse', self.url):
                return 1
            else:
                return -1
        except:
            return -1

    def Redirect(self):
        """
        Redirect

        :return:

        The presence of “<meta>” HTML tag in the URL is a strong indicator of phishing websites.
        This feature checks for the presence of “<meta>” tag in the URL.

        If the URL has “<meta>” tag, the value assigned to this feature is 1 (phishing) or else -1 (legitimate).

        """
        try:
            if self.soup.find('meta', attrs={'http-equiv': 'refresh'}):
                return 1
            else:
                return -1
        except Exception as err:
            return -1

    def on_mouseover(self):
        """

        :return:


        Status Bar Customization

        Phishers may use JavaScript to show a fake URL in the status bar to users.

        To extract this feature, we must dig-out the webpage source code, particularly the “onMouseOver” event,
        and check if it makes any changes on the status bar

        If the response is empty or onmouseover is found then, the value
        assigned to this feature is 1 (phishing) or else 0 (legitimate).

        """
        try:
            if re.findall(r"onmouseover", self.soup.text):
                return 1
            else:
                return -1
        except Exception as err:
            return -1

    def RightClick(self):
        """
        RightClick

        :return:

        Disabling Right Click

        Phishers use JavaScript to disable the right-click function, so that users cannot view and
        save the webpage source code. This feature is treated exactly as “Using onMouseOver to hide the Link”.

        Nonetheless, for this feature, we will search for event “event.button==2” in the webpage source code and
        check if the right click is disabled.

        If the response is empty or onmouseover is not found then, the value assigned to this
        feature is 1 (phishing) or else 0 (legitimate).

        """
        try:
            if re.findall(r"contextmenu|event.button ?== ?2", self.soup.text):
                return 1
            else:
                return -1
        except Exception as err:
            return -1

    def popUpWidnow(self):
        """

        :return:

        PopUp Window

        Phishers may use JavaScript to open a fake webpage in a new window to trick users.

        This feature is treated exactly as “Using onMouseOver to hide the Link”.

        Nonetheless, for this feature, we will search for event “window.open” in the webpage source
        code and check if the pop-up window is opened.

        If the response is empty or onmouseover is not found then, the value
        assigned to this feature is 1 (phishing) or else 0 (legitimate).

        """
        try:
            if re.findall(r"alert\(|onMouseOver|window.open", self.soup.text):
                return 1
            else:
                return -1
        except Exception as err:
            return -1

    def Iframe(self):
        """
        Iframe

        :return:


        IFrame Redirection

        IFrame is an HTML tag used to display an additional webpage into one that is currently shown.

        Phishers can make use of the “iframe” tag and make it invisible i.e. without frame borders.

        In this regard, phishers make use of the “frameBorder” attribute which causes the browser to
        render a visual delineation. If the iframe is empty or repsonse is not found then,
        the value assigned to this feature is 1 (phishing) or else -1 (legitimate).

        """
        try:
            if re.findall(r"[<iframe>|<frameBorder>]", self.soup.text):
                return 1
            else:
                return -1
        except Exception as err:
            return -1

    def age_of_domain(self):
        """
        age_of_domain

        :return:

        This feature can be extracted from WHOIS database. Most phishing websites live for a short period of time.

        The minimum age of the legitimate domain is considered to be 12 months for this project.
        Age here is nothing but different between creation and expiration time.

        If age of domain > 12 months, the vlaue of this feature is 1 (phishing) else -1 (legitimate).

        """
        if self.whois is None:
            return 1

        try:
            if type(self.whois['creation_date']) is list:
                creation_date = self.whois['creation_date'][0]
            else:
                creation_date = self.whois['creation_date']

            ageofdomain = abs((datetime.datetime.now() - creation_date).days)
            if ageofdomain / 30 > 12:
                return -1
            else:
                return 1
        except Exception as err:
            return 1

    def DNSRecord(self):
        """
        DNSRecord

        :return:


        For phishing websites, either the claimed identity is not recognized by the WHOIS database or no records
        founded for the hostname.

        If the DNS record is empty or not found then, the value assigned to this
        feature is 1 (phishing) or else -1 (legitimate).

        """
        try:
            resolver.resolve(self.domain, 'A')
            return -1
        except Exception as err:
            return 1

    def web_traffic(self):
        """
        web_traffic

        :return:


        This feature measures the popularity of the website by determining the number of visitors and the number
        of pages they visit. However, since phishing websites live for a short period of time,
        they may not be recognized by the Alexa database (Alexa the Web Information Company., 1996).
        By reviewing our dataset, we find that in worst scenarios, legitimate websites ranked among the top
        100,000. Furthermore, if the domain has no traffic or is not recognized by the Alexa database, it
        is classified as “Phishing”.

        If the rank of the domain < 100000, the vlaue of this feature is 1 (phishing) else -1 (legitimate).

        """
        try:
            alexadata = BeautifulSoup(requests.get(
                "http://data.alexa.com/data?cli=10&dat=s&url=" + self.domain, timeout=10).content, 'lxml')
            rank = int(alexadata.find('reach')['rank'])
            if rank < 100000:
                return -1
            else:
                return 1
        except Exception as err:
            return 1
