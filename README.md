# Phish Hunter AI

Phish Hunter is a Machine Learning Artificial Intelligence application
developed to analyze URLs, obtain various datapoints and make a prediction
to if it is a valid Phishing website or not.

Phish Hunter follows the "Phishing Websites Features" outlined and documented by
Rami M. Mohammad, Fadi Thabtah and Lee McCluskey.

The dataset used in this version has been changed from the original to remove the
page_rank, google_index ,links_pointing_to_page, and statistical_report datapoints
as there is some complications obtaining that data due to situations like Google
blocking users from making search request from code.

Though these data points have been removed, this new design and trained data model
still holds a 95% prediction success rate.

My goal is too add additional datapoints to counter the removal of the 4 mentioned
above, but this may take some time as it will require me to build a new and
custom dataset for training purposes since the original URLs used to build the 
original training dataset were not included in any of the publications
that I was able to locate.

Furthermore, while this project could be expanded with a Flask interface for allowing
users to make requests via a provided web service, I have decided to write this
project in a way that will make it usable by many projects and so that you 
can "import" it into your own Python applications to create Internet crawlers,
web services, and tools to protect your corporate employees and clients.

For the dataset, saved pickle, and website features outline please see the 
original_publications/* directory. With some modifications, and new functions in
the libs/features.py you could bring the original version back should you have
the desire to do so.

Enjoy

## Getting Started

Clone the repository, create your Python Virtual Environment, install the requirements
and run.

```bash
git clone https://github.com/h4cklife/phish_hunter.git
...

$ cd phish_hunter
$ python3 -m venv venv
$ source venv/bin/activate
$ pip install -r requirements.txt
...

$ python phish_hunter.py
```

## Use cases

If you haven't already, make sure you are in your environment.

```bash
$ source venv/bin/activate
```

## Create A Dataset

```bash
$ python create_phish_hunter_csv.py -l 25 -i new_data_urls.csv -o dataset.csv

             ▄▄▄· ▄ .▄▪  .▄▄ ·  ▄ .▄     ▄ .▄▄• ▄▌ ▐ ▄ ▄▄▄▄▄▄▄▄ .▄▄▄
            ▐█ ▄███▪▐███ ▐█ ▀. ██▪▐█    ██▪▐██▪██▌•█▌▐█•██  ▀▄.▀·▀▄ █·
             ██▀·██▀▐█▐█·▄▀▀▀█▄██▀▐█    ██▀▐██▌▐█▌▐█▐▐▌ ▐█.▪▐▀▀▪▄▐▀▀▄
            ▐█▪·•██▌▐▀▐█▌▐█▄▪▐███▌▐▀    ██▌▐▀▐█▄█▌██▐█▌ ▐█▌·▐█▄▄▌▐█•█▌
            .▀   ▀▀▀ ·▀▀▀ ▀▀▀▀ ▀▀▀ ·    ▀▀▀ · ▀▀▀ ▀▀ █▪ ▀▀▀  ▀▀▀ .▀  ▀
·▄▄▄▄   ▄▄▄· ▄▄▄▄▄ ▄▄▄· .▄▄ · ▄▄▄ .▄▄▄▄▄     ▄▄· ▄▄▄  ▄▄▄ . ▄▄▄· ▄▄▄▄▄      ▄▄▄
██▪ ██ ▐█ ▀█ •██  ▐█ ▀█ ▐█ ▀. ▀▄.▀·•██      ▐█ ▌▪▀▄ █·▀▄.▀·▐█ ▀█ •██  ▪     ▀▄ █·
▐█· ▐█▌▄█▀▀█  ▐█.▪▄█▀▀█ ▄▀▀▀█▄▐▀▀▪▄ ▐█.▪    ██ ▄▄▐▀▀▄ ▐▀▀▪▄▄█▀▀█  ▐█.▪ ▄█▀▄ ▐▀▀▄
██. ██ ▐█ ▪▐▌ ▐█▌·▐█ ▪▐▌▐█▄▪▐█▐█▄▄▌ ▐█▌·    ▐███▌▐█•█▌▐█▄▄▌▐█ ▪▐▌ ▐█▌·▐█▌.▐▌▐█•█▌
▀▀▀▀▀•  ▀  ▀  ▀▀▀  ▀  ▀  ▀▀▀▀  ▀▀▀  ▀▀▀     ·▀▀▀ .▀  ▀ ▀▀▀  ▀  ▀  ▀▀▀  ▀█▄▀▪.▀  ▀
  \_____)\_____
  /--v____ __`<  Phish hunter Artifical Intelligence version 1.00
          )/
          '

Loading input data for phish/legitimate website urls...
Creating the Phish Hunter dataset...
Loading 394561 phishing URLs...
Loading 426754 non-phishing URLs...
Processing phish URL : ...
...
...
...
Phish Hunter's AI Training Data file 'dataset.csv' has been written successfully.
```


## Train the AI Model

```bash
$ python train_phish_hunter.py
usage: analyze_url [-h] [-d DATASET] [-o DOT] [-m MATRIX]

Analyze a URL for debugging the Phish Hunter ML AI

options:
  -h, --help            show this help message and exit
  -d DATASET, --dataset DATASET
  -o DOT, --dot DOT
  -m MATRIX, --matrix MATRIX


```

Unless you have renamed the dataset, the command below will work right off the rip of a git clone of this repository.

```bash
$ python train_phish_hunter.py -d dataset.csv -o tree.dot -m confusion_matrix.png

              ▄▄▄▄▄▄▄▄   ▄▄▄· ▪   ▐ ▄ ▪   ▐ ▄  ▄▄ •
              •██  ▀▄ █·▐█ ▀█ ██ •█▌▐███ •█▌▐█▐█ ▀ ▪
               ▐█.▪▐▀▀▄ ▄█▀▀█ ▐█·▐█▐▐▌▐█·▐█▐▐▌▄█ ▀█▄
               ▐█▌·▐█•█▌▐█ ▪▐▌▐█▌██▐█▌▐█▌██▐█▌▐█▄▪▐█
               ▀▀▀ .▀  ▀ ▀  ▀ ▀▀▀▀▀ █▪▀▀▀▀▀ █▪·▀▀▀▀
    ▄▄▄· ▄ .▄▪  .▄▄ ·  ▄ .▄     ▄ .▄▄• ▄▌ ▐ ▄ ▄▄▄▄▄▄▄▄ .▄▄▄
   ▐█ ▄███▪▐███ ▐█ ▀. ██▪▐█    ██▪▐██▪██▌•█▌▐█•██  ▀▄.▀·▀▄ █·
    ██▀·██▀▐█▐█·▄▀▀▀█▄██▀▐█    ██▀▐██▌▐█▌▐█▐▐▌ ▐█.▪▐▀▀▪▄▐▀▀▄
   ▐█▪·•██▌▐▀▐█▌▐█▄▪▐███▌▐▀    ██▌▐▀▐█▄█▌██▐█▌ ▐█▌·▐█▄▄▌▐█•█▌
   .▀   ▀▀▀ ·▀▀▀ ▀▀▀▀ ▀▀▀ ·    ▀▀▀ · ▀▀▀ ▀▀ █▪ ▀▀▀  ▀▀▀ .▀  ▀
\_____)\_____
 /--v____ __`<  Phish hunter Artifical Intelligence version 1.00
         )/
         '

[+] Staring Phish Hunter AI Training Mode...
[+] Loading the dataset...
[+] Splitting data into Train and Test data...
[+] Creating Model Decision Tree Classifier...
[+] Fitting data and training the Model...
[+] Making predictions with Xtest...

              precision    recall  f1-score   support

          -1       1.00      0.75      0.86         8
           1       0.71      1.00      0.83         5

    accuracy                           0.85        13
   macro avg       0.86      0.88      0.85        13
weighted avg       0.89      0.85      0.85        13

Accuracy Score: 85.0 %

[+] Saving Confusion Matrix...
[+] Saving dot file...
[+] Converting dot file to image...
[+] Saving the model to file for later use...
[+] DONE!
```


## Analyze a URL

I would like to circle back and break down each point so you can understand the
datapoint that determined the result like I did with the Length, but
I will come back to this. For now, here is a starting point.

```bash
$ python analyze_url.py
usage: analyze_url [-h] [-u URL] [-a] [-d]

Analyze a URL for debugging the Phish Hunter ML AI

options:
  -h, --help         show this help message and exit
  -u URL, --url URL
  -a, --array
  -d, --dict
```

```bash
$ python analyze_url.py -u https://welcome-doc-exodus.github.io/en-us/ -a
...
[-1, -1, -1, -1, -1, 1, -1, -1, 1, 1, -1, -1, -1, -1, 1, -1, -1, -1, -1, -1, -1, -1, 1, 1, -1, 1]

$ python analyze_url.py -u https://welcome-doc-exodus.github.io/en-us/ -d
...
{
    "having_IP_Address": -1,
    "URL_Length": -1,
    "Shortining_Service": -1,
    "having_At_Symbol": -1,
    "double_slash_redirecting": -1,
    "Prefix_Suffix": 1,
    "having_Sub_Domain": -1,
    "SSLFinal_State": -1,
    "Domain_registeration_length": 1,
    "Favicon": 1,
    "port": -1,
    "HTTPS_token": -1,
    "Request_URL": -1,
    "URL_of_Anchor": -1,
    "Links_in_tags": 1,
    "SFH": -1,
    "Submitting_to_email": -1,
    "Abnormal_URL": -1,
    "Redirect": -1,
    "on_mouseover": -1,
    "RightClick": -1,
    "popUpWidnow": -1,
    "Iframe": 1,
    "age_of_domain": 1,
    "DNSRecord": -1,
    "web_traffic": 1
}
```

## Run Phish Hunter

Eventually, I plan to include an application that can crawl the entire internet, detect 
websites and scan each while generating results into a report. ....maybe?

Yes, I know after training the model it says the accuracy is 95%, but it is not always 95%. 
...on the other hand 95% compared to what, in reality?

I could grab 50 URLs that are obvious to the eye and obtain 100% accuracy in the results.
I could grab 50 random URLS and get ~50% accuracy.
I could grab 50 super smart URLs by intelligent threat actors and get ~10% accuracy.

Threat actors are just as capable as the blue teamers. Don't think, they aren't using 
the same codes and datasets to test and craft the perfect URLs to circumvent these 
types of tools.

I would...

After all, this is based off of a public, publication...

Have fun,

```bash
$ python phish_hunter.py
usage: phish_hunter [-h] [-u URL] [-r] [-a APPEND_DATASET]

Analyze a URL to determine if it may be a Phishing site

options:
  -h, --help            show this help message and exit
  -u URL, --url URL
  -r, --run_internal_links
  -a APPEND_DATASET, --append_dataset APPEND_DATASET
```

```bash
$ python phish_hunter.py -r -a new_dataset.csv
[-] 1 - https://mondialrelaylivraison.net/ is PHISH: False
[-] 2 - https://verif0785portal.info/purduefeds is PHISH: False
[*] 3 - https://www.irs.gov.tax-sioe.com/ is PHISH: True
[-] 4 - https://rebrand.ly/gpdpcxz is PHISH: False
[-] 5 - https://gt.membersitogo.4pu.com/plan is PHISH: False
[*] 6 - http://allegrolokalnie.pl-4637347.icu is PHISH: True
[-] 7 - https://serve.tigo-gt.top/gt?hWK=RyR4orilLs is PHISH: False
[*] 8 - http://allegrolokalnie.pl-oferta9431404.cfd is PHISH: True
[-] 9 - http://d0pd.841518.cfd/ is PHISH: False
[-] 10 - https://welcome-doc-exodus.github.io/en-us/ is PHISH: False
[*] 11 - https://s-push-erneuerung.com/ is PHISH: True
[*] 12 - https://bigalmechanical.com/-/dbag/ is PHISH: True
[*] 13 - https://package-expressdh.com/captcha/captcha.php is PHISH: True
[*] 14 - https://docs.google.com/presentation/d/e/2PACX-1vTr4Eb70TIUMSkdwL9Q2twDWru9LVq6C_4dj2g_xQ_12QoHrbeH-p9Fw9eJ2vGUFKiP64-eTSb1r1hS/pub?start=false&loop=false&delayms=3000 is PHISH: True
[-] 15 - https://f6d19e18.outh-sam20.pages.dev/ is PHISH: False
[-] 16 - https://e025441b.currentllyy.pages.dev/ is PHISH: False
[-] 17 - https://metanetfixx.pages.dev/connect is PHISH: False
[*] 18 - https://package-expressdh.com/captcha/captcha.php is PHISH: True
[*] 19 - http://vz2wssfi.r.us-east-1.awstrack.me/L0/9uy8t76dytxcvyubhijpohikgnytrgwsdtyuigohojigu.pages.dev%2F%3FD5kcy5grsNUHE0gZ4sKOUP4jkHyJXMDitQmieP5mgGRvzlGSgmUwAl/1/01000194dd66b512-c7ca596e-9acd-4604-8b07-178de31095b1-000000/CuLVPdOnU5xiffpFq3V-MyrkJAc=412 is PHISH: True
[-] 20 - http://itauresgatedepontos.dynv6.net/ is PHISH: False
[*] 21 - https://disponivelparavoce.dynv6.net/cliente/cadrastro.php?codigo=XIHl7gXN4LkHDgTmq2xJu6ZWU-pFJCfIKE0oMWT3YFdKF is PHISH: True
[*] 22 - https://duxyy3sx96.com/index/login/login/token/e116e1304ce834694c37f2c53778894d.html is PHISH: True
[*] 23 - https://z7r7433fo3.vip/index/login/login/token/e116e1304ce834694c37f2c53778894d.html is PHISH: True
[*] 24 - https://duxyy3sx96.vip/index/login/login/token/e116e1304ce834694c37f2c53778894d.html is PHISH: True
[*] 25 - https://rzs6ji6bq0.vip/index/login/login/token/e116e1304ce834694c37f2c53778894d.html is PHISH: True
[*] 26 - https://tldbrrqcmj.vip/index/login/login/token/e116e1304ce834694c37f2c53778894d.html is PHISH: True
[-] 27 - https://slgndocline.onlxtg.com/87300038978/ is PHISH: False
[-] 28 - https://viaoceanica.com/jpd/index.htm is PHISH: False
[-] 29 - http://sjfqvcxbee.cfolks.pl/ab/ar is PHISH: False
[*] 30 - https://pay.shopeeprodutos.site/lDW0ZaKOBaQgN7E?utm_source=organic&utm_campaign=&utm_medium=&utm_content=&utm_term=&subid=&sid2=&subid2=&subid3=&subid4=&subid5=&xcod=&sck= is PHISH: True
[*] 31 - https://pay.pagmenos.site/YEwR3ADR7dogdKy?utm_source=organic&utm_campaign=rKm-km-rKm&utm_medium=&utm_content=&utm_term=&xcod=jLj67a1f0eef317b016cee2cca3hQwK21wXxRrKm-km-rKmhQwK21wXxRhQwK21wXxRhQwK21wXxR&sck=jLj67a1f0eef317b016cee2cca3hQwK21wXxRrKm-km-rKmhQwK21wXxRhQwK21wXxRhQwK21wXxR is PHISH: True
[-] 32 - https://f6d19e18.outh-sam20.pages.dev/?id=ev7BHk51p2 is PHISH: False
```