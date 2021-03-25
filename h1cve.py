import tweepy
import requests
import json
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from extract import json_extract
from time import sleep
from requests.adapters import HTTPAdapter
from urllib3.util import Retry

# get environment variables from .env
load_dotenv()

# try the OS variables (just in case for Heroku)
consumer_key = os.environ.get("API_KEY")
consumer_secret_key = os.environ.get("API_SECRET_KEY")
access_token = os.environ.get("ACCESS_TOKEN")
access_token_secret = os.environ.get("ACCESS_TOKEN_SECRET")

# Authenticate to Twitter
auth = tweepy.OAuthHandler(consumer_key, consumer_secret_key)
auth.set_access_token(access_token, access_token_secret)
twitta = tweepy.API(auth)

# get current time and adjust timedelta to script cron period
adjusted_date_time = datetime.now() - timedelta(hours=1)

nvd_date_time = adjusted_date_time.strftime(
    "%Y-%m-%dT%H:%M:%S:000 UTC-05:00"
)  # NVD API needs: yyyy-MM-dd'T'HH:mm:ss:SSS z

# National Vulnerability Database (NVD) API documented here: https://bit.ly/3bqcxYk
api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"
site_url = "https://nvd.nist.gov/vuln/detail/"

# NVD API search parameters
params = {
    "keyword": "hackerone",  # search for keyword "hackerone"
    "startIndex": 0,  # start at most recent CVEs
    "resultsPerPage": 50,  # page big enough for all results at once
    "pubStartDate": nvd_date_time,
}


# Retry request function. NVD API can be rather unresponsive
def requests_retry_session(
    retries=10,
    backoff_factor=0.5,
    status_forcelist=(500, 502, 504),
    session=None,
):
    session = session or requests.Session()
    retry = Retry(
        total=retries,
        read=retries,
        connect=retries,
        backoff_factor=backoff_factor,
        status_forcelist=status_forcelist,
    )
    adapter = HTTPAdapter(max_retries=retry)
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    return session


def get_cves():
    """
    This function pulls CVEs from NVD in the specified time period and order
    :return: It returns a list
    """
    print("starting get_CVEs\n")

    try:
        response = requests_retry_session().get(api_url, params=params, timeout=10)
        response.raise_for_status()
        print("NVD API status code: " + str(response.status_code) + "\n")
    except requests.exceptions.HTTPError as errh:
        print("HTTP Error:", errh)
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
    except requests.exceptions.RequestException as err:
        print("OOps: Something Else", err)

    # parse the json response
    global master_dict
    id_list = json_extract(response.json(), "ID")
    url_list = json_extract(response.json(), "url")
    h1_url_list = [i for i in url_list if "hackerone" in i]
    master_dict = dict(zip(id_list, h1_url_list))
    print("end get_CVEs\n")


def tweet_cves():
    """
    This function updates the Twitter timeline with discovered CVEs
    :return: It has no return value
    """
    print("printing CVEs found here:\n")
    for cve, h1_url in master_dict.items():
        tweet = (
            cve
            + " reported via @Hacker0x01 has been published: "
            + site_url
            + cve
            + "\r\n\r\n"
            + h1_url
        )
        try:
            twitta.update_status(tweet)
            print(tweet)
            sleep(2)
        except tweepy.TweepError as e:
            print('Twitter error: ', e.response.text)
            pass


if __name__ == "__main__":
    while True:
        try:
            get_cves()
            tweet_cves()
            print("\ndone")
        except Exception as exc:
            print(exc)
        # check every hour
        sleep(60 * 60)