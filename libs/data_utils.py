import os
import uuid
import requests
import csv
import cv2
import whois
import dns.resolver
import numpy as np
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from skimage.metrics import structural_similarity as ssim
from urllib.parse import urlparse

class colors:
    """
    Terminal colors
    """
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKCYAN = '\033[96m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'


def write_to_file(file_path, row):
    """
    Write a csv line to the file

    :param str file_path: Path to the output file
    :param list row: CSV row

    :return:
    """
    # Open the file in write mode ('w')
    file_out = open(file_path, 'a', newline='')
    writer = csv.writer(file_out)
    writer.writerow(row)
    file_out.close()

def download_content(url):
    """
    Downloads HTML content from a URL and 
    returns the response.text

    :param str url: URL of the website

    :return str: Response text
    """
    try:
        response = requests.get(url)
        response.raise_for_status() # Raise HTTPError for bad responses (4xx or 5xx)

        return response.text
    except requests.exceptions.RequestException as e:
        return None

def get_dns_records(domain, record_type):
    """
    Get DNS records and return the record type

    Usage:
        domain = "example.com" # Replace with your domain
        record_types = ['A', 'MX', 'NS', 'TXT', 'CNAME'] # Select the desired record types

        for record_type in record_types:
            get_dns_records(domain, record_type)

    :param str domain: Domain
    :param str record_type: DNS Record type to obtain and return
    
    :return:
    """
    try:
        resolver = dns.resolver.Resolver()
        answers = resolver.resolve(domain, record_type)
        #for rdata in answers:
        #    print(rdata)
        return answers
    except dns.resolver.NoAnswer:
        #print(f"No {record_type} records found for {domain}")
        return None
    except dns.resolver.NXDOMAIN:
        #print(f"Domain {domain} does not exist")
        return 'nxdomain'
    except dns.resolver.LifetimeTimeout as e:
        return 'timeout'
    except Exception as e:
        #print(f"An error occurred obtaining DNS record: {e}")
        return None

def is_domain_on_hold(domain):
    """
    Checks for a clientHold/serverHold
    If there is an error, the site is considered offline
    If there are no statuses, the site is considered offline

    :param str domain: The domain of the target website

    :return bool: 
    """
    try:
        domain_whois = whois.whois(domain)
    except whois.parser.PywhoisError as e:
        return True
    except Exception as e:
        return True
    
    statuses = domain_whois.get('status')

    if statuses:
        for status in statuses:
            if 'clientHold' in status or 'serverHold' in status:
                return True
    elif not statuses:
        return False
    
    return False

def get_root_domain(url):
    """
    Extract the root domain

    :param str url: URL of the website

    :return str: Domain
    """
    parsed_url = urlparse(url)

    domain_parts = parsed_url.netloc.split('.')

    if len(domain_parts) > 1:
      root_domain = '.'.join(domain_parts[-2:])
    else:
      root_domain = parsed_url.netloc
    return root_domain

def get_host_domain(url):
    """
    Extract the host domain

    :param str url: URL of the website

    :return str: Domain
    """
    parsed_url = urlparse(url)
    host_domain = parsed_url.netloc
    return host_domain

def get_grayscale(image):
    """
    Grayscale image

    :param str image: Image to apply cv2 option to
    
    :return: Image
    """
    return cv2.cvtColor(image, cv2.COLOR_BGR2GRAY)

def remove_noise(image):
    """
    Remove noise from image

    :param str image: Image to apply cv2 option to
    
    :return: Image
    """
    return cv2.medianBlur(image,5)

def thresholding(image):
    """
    Threashholding of image

    :param str image: Image to apply cv2 option to
    
    :return: Image
    """
    return cv2.threshold(image, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)[1]

def dilate(image):
    """
    Dilate image
    
    :param str image: Image to apply cv2 option to
    
    :return: Image
    """
    kernel = np.ones((5,5),np.uint8)
    return cv2.dilate(image, kernel, iterations = 1)
    
def erode(image):
    """
    Erode image

    :param str image: Image to apply cv2 option to
    
    :return: Image
    """
    kernel = np.ones((5,5),np.uint8)
    return cv2.erode(image, kernel, iterations = 1)

def opening(image):
    """
    Opening - erosion followed by dilation

    :param str image: Image
    
    :return: Image
    """
    kernel = np.ones((5,5),np.uint8)
    return cv2.morphologyEx(image, cv2.MORPH_OPEN, kernel)

def canny(image):
    """
    Canny edge detection

    :param str image: Image
    
    :return: Image
    """
    return cv2.Canny(image, 100, 200)

def deskew(image):
    """
    Skew correction

    :param str image: Image
    
    :return: Image
    """
    coords = np.column_stack(np.where(image > 0))
    angle = cv2.minAreaRect(coords)[-1]
    if angle < -45:
        angle = -(90 + angle)
    else:
        angle = -angle
    (h, w) = image.shape[:2]
    center = (w // 2, h // 2)
    M = cv2.getRotationMatrix2D(center, angle, 1.0)
    rotated = cv2.warpAffine(image, M, (w, h), flags=cv2.INTER_CUBIC, borderMode=cv2.BORDER_REPLICATE)
    return rotated

#template matching
def match_template(image, template):
    """
    Template matching

    :param str image: Image
    :param str template: Template

    :return: Template match
    """
    return cv2.matchTemplate(image, template, cv2.TM_CCOEFF_NORMED)
    
def compare_images(target_path, legit_path):
    """
    Compare images

    :param str target_path: Target image path
    :param str legit_path: Legit image path

    :return: MSE and SSIM Value
    """
    img1 = cv2.imread(target_path, cv2.IMREAD_GRAYSCALE)
    img2 = cv2.imread(legit_path, cv2.IMREAD_GRAYSCALE)

    if img1 is None or img2 is None:
        print("Error: Could not load one or both images.")
        return

    if img1.shape != img2.shape:
       img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))

    mse = np.mean((img1 - img2) ** 2)
    ssim_value = ssim(img1, img2, data_range=img2.max() - img2.min())

    #print(f"MSE: {mse:.2f}")
    #print(f"SSIM: {ssim_value:.2f}")

    diff = cv2.absdiff(img1, img2)
    _, thresh = cv2.threshold(diff, 25, 255, cv2.THRESH_BINARY)
    
    return mse, ssim_value


def get_target_screenshot(target_url):
    """
    Get Target URL and Legit URL Screenshots

    :param str target_url: Target URL
    :param str legit_url: Legit URL

    :return: MSE and SSIM Value
    """
    # Define a function to get scroll dimensions
    def get_scroll_dimension(axis):
        return driver.execute_script(f"return document.body.parentNode.scroll{axis}")

    # Get Target Screenshot

    if "http" not in target_url:
        target_url = f"http://{target_url}"

    # Run Chrome in headless mode
    options = Options()
    options.add_argument("--headless")

    # Start a driver instance
    driver = webdriver.Chrome(options=options)
    # Open the target website

    # Try to get the target_url screenshot
    # if this fails, the site is offline
    # and was likely a phish (1) since
    # phish usually have a short lifespan
    try:
        driver.set_page_load_timeout(10)
        driver.get(target_url)
        # Get the page scroll dimensions
        width = get_scroll_dimension("Width")
        height = get_scroll_dimension("Height")
        # Set the browser window size
        driver.set_window_size(width, height)
        # Get the full body element
        full_body_element = driver.find_element(By.TAG_NAME, "body")
        # Take a full-page screenshot
        target_filename = str(uuid.uuid4())
        target_image_path = f"tmp/{target_filename}.png"
        full_body_element.screenshot(target_image_path)
    except Exception as exp:
        pass

    if target_image_path:
        return target_image_path
    else:
        return None

def get_target_and_legit_screenshots(target_url, legit_url):
    """
    Get Target URL and Legit URL Screenshots

    :param str target_url: Target URL
    :param str legit_url: Legit URL

    :return: MSE and SSIM Value
    """
    # Define a function to get scroll dimensions
    def get_scroll_dimension(axis):
        return driver.execute_script(f"return document.body.parentNode.scroll{axis}")

    # Get Target Screenshot

    if "http" not in target_url:
        target_url = f"http://{target_url}"

    # Run Chrome in headless mode
    options = Options()
    options.add_argument("--headless")

    # Start a driver instance
    driver = webdriver.Chrome(options=options)
    # Open the target website

    # Try to get the target_url screenshot
    # if this fails, the site is offline
    # and was likely a phish (1) since
    # phish usually have a short lifespan
    try:
        driver.set_page_load_timeout(10)
        driver.get(target_url)
        # Get the page scroll dimensions
        width = get_scroll_dimension("Width")
        height = get_scroll_dimension("Height")
        # Set the browser window size
        driver.set_window_size(width, height)
        # Get the full body element
        full_body_element = driver.find_element(By.TAG_NAME, "body")
        # Take a full-page screenshot
        target_filename = str(uuid.uuid4())
        target_image_path = f"tmp/{target_filename}.png"
        full_body_element.screenshot(target_image_path)
    except Exception as exp:
        pass
    
    # Get legit image

    if "http" not in legit_url:
        legit_url = f"http://{legit_url}"

    # Run Chrome in headless mode
    options = Options()
    options.add_argument("--headless")

    # Start a driver instance
    driver = webdriver.Chrome(options=options)

    try:
        driver.set_page_load_timeout(10)
        # Open the target website
        driver.get(legit_url)
        # Get the page scroll dimensions
        width = get_scroll_dimension("Width")
        height = get_scroll_dimension("Height")
        # Set the browser window size
        driver.set_window_size(width, height)
        # Get the full body element
        full_body_element = driver.find_element(By.TAG_NAME, "body")
        # Take a full-page screenshot
        legit_filename = str(uuid.uuid4())
        legit_image_path = f"tmp/{legit_filename}.png"
        full_body_element.screenshot(legit_image_path)
    except Exception as exp:
        pass
    
    if os.path.exists(legit_image_path) or os.path.exists(target_image_path):
        if target_image_path and legit_image_path:
            return target_image_path, legit_image_path
        elif not target_image_path:
            if legit_image_path:
                return None, legit_image_path
        elif not legit_image_path:
            if target_image_path:
                return target_image_path, None
        else:
            return None, None
    else:
        return None, None


blacklist_chars = [
'ì',
'ê',
'ã',
'Õ',
'»',
'Î',
'§',
'é',
'Î',
'½',
'ñ',
'¡',
'â',
'â',
'ò',
'¸',
'à',
';',
'Í',
'¾',
'@',
'Ò',
'Ê',
'¹',
'Ë',
'¨',
'ö',
'í',
'§',
';',
'¬',
'Ô',
'è',
'è',
'é',
'¨',
'ø',
'í',
'Ì',
'[',
'½',
'=',
'ÿ',
'Ã',
'»',
'r',
'â',
'æ',
'ô',
'µ',
'}',
'»',
'´',
'Â',
'Ï',
'4',
'¿',
'ª',
'¡',
'j',
'"',
'>',
')',
'¬',
'Ý',
'ì',
'Ã',
'w',
'!',
'Ô',
'£',
'ã',
'W',
'§',
'&',
'£',
'Ñ',
'$',
'Þ',
'ô',
'ö',
'Ý',
'Y',
'Ö',
'þ',
'ß',
'ï',
'Ð',
'º',
'Ð',
'ã',
'ì',
'ý',
'Õ',
'Å',
'ç',
'Ò',
'¹',
'ó',
'¬',
'é',
'í',
'}',
'·',
'Á',
'ª',
'í',
'_',
'¢',
'Ø',
'Ø',
'ò',
'0',
'ú',
'Þ',
'ñ',
'½',
'Ó',
'µ',
'»',
'ç',
'^',
'Æ',
'!',
'¯',
'ì',
'½',
'ú',
'°',
'ï',
'õ',
'ï',
'£',
'␦',
'Õ',
'±',
'Ç',
'»',
'ê',
'ù',
'ú',
'#',
'Ò',
'u',
'ü',
'ö',
'%',
'Æ',
'å',
'ð',
'û',
'Ï',
'ù',
'Ë',
'Ó',
'Ã',
'æ',
'',
'¾',
'÷',
'Ö',
'Ó',
'ê',
'ý',
'ü',
'É',
'°',
'õ',
'Ù',
'¹',
'Ì',
'Ñ',
'ê',
'F',
'Ä',
'ò',
'ï',
'¦',
'[',
'0',
'ò',
'>',
'Þ',
'j',
'®',
'Æ',
'e',
'à',
'ù',
'-',
'í',
'à',
'Ç',
'$',
'¤',
'ë',
'È',
'²',
'ú',
'Ì',
'¶',
'á',
'ò',
'°',
'i',
'°',
'þ',
'[',
'«',
'³',
'»',
']',
'¹',
'§',
';',
'¬',
'Ô',
'A',
'è',
'U',
'è',
'é',
'¨',
'ø',
'í',
'Ì',
'½ÿ',
'Ã',
'»',
'â',
'æ',
'ô',
'µ',
'»',
'´',
'Â',
'Ï',
'¿',
'ª',
'ó',
'0',
'â',
'Õ',
'á',
'¤',
'ò',
'¡',
'¨',
'¨',
'¼',
'é',
'ý',
'Ö',
'Ò',
'%',
'Ó',
'é',
'þ',
'ù',
'ü',
'?',
'¹',
'¯',
'ú',
'£',
'ù',
'Ù',
'î',
'¬',
'æ',
'Ì',
'ì',
'×',
'Ë',
'õ',
'³',
'¯',
'=',
'Í',
]