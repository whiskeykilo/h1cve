import os
from datetime import datetime, timedelta
from time import sleep
import requests
from dotenv import load_dotenv
import tweepy
from requests.adapters import HTTPAdapter
from urllib3.util import Retry
from extract import json_extract

# get environment variables from .env
load_dotenv()

# try the OS variables (just in case for Heroku)
nvd_key = os.environ.get("NVD_KEY")
consumer_key = os.environ.get("TWITTER_API_KEY")
consumer_secret_key = os.environ.get("TWITTER_API_SECRET_KEY")
access_token = os.environ.get("TWITTER_ACCESS_TOKEN")
access_token_secret = os.environ.get("TWITTER_ACCESS_TOKEN_SECRET")

# load Twitter variables
auth = tweepy.OAuthHandler(consumer_key, consumer_secret_key)
auth.set_access_token(access_token, access_token_secret)
twitta = tweepy.API(auth)

# National Vulnerability Database (NVD) API documented here: https://bit.ly/3bqcxYk
API_URL = "https://services.nvd.nist.gov/rest/json/cves/1.0"
SITE_URL = "https://nvd.nist.gov/vuln/detail/"


def requests_retry_session(
    retries=3,
    backoff_factor=0.3,
    status_forcelist=(500, 502, 504),
    session=None,
):
    """
    Retry request function. NVD API can be rather unresponsive:
    https://www.peterbe.com/plog/best-practice-with-retries-with-requests
    :return: Returns the session details
    """
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


def poll_nvd():
    """
    This function pulls CVEs from NVD in the specified time period and order
    :return: It returns a list
    """
    print("polling the NVD\n")

    # get current time
    datetime_now = datetime.now()

    # adjust timedelta to script cron period
    # adjusted_date_time = datetime_now - timedelta(hours=1)  # prod
    adjusted_date_time = datetime_now - timedelta(days=10)  # test

    nvd_datetime = adjusted_date_time.strftime(
        "%Y-%m-%dT%H:%M:%S:000 UTC-05:00"
    )  # NVD API needs: yyyy-MM-dd'T'HH:mm:ss:SSS z

    nvd_datetime_now = datetime_now.strftime(
        "%Y-%m-%dT%H:%M:%S:000 UTC-05:00"
    )  # NVD API needs: yyyy-MM-dd'T'HH:mm:ss:SSS z

    # NVD API search parameters
    params = {
        "keyword": "hackerone",  # search for keyword "hackerone"
        "startIndex": 0,  # start at most recent CVEs
        "resultsPerPage": 50,  # page big enough for all results at once
        "pubStartDate": nvd_datetime,
        "pubEndDate": nvd_datetime_now,
    }
    try:
        response = requests_retry_session().get(
            API_URL, params=params, timeout=(3.05, 10)
        )
        response.raise_for_status()
        print("NVD API status code: " + str(response.status_code) + "\n")
    except requests.exceptions.HTTPError as errh:
        print("HTTP Error " + str(response.status_code) + ":\n", errh)
    except requests.exceptions.ConnectionError as errc:
        print("Error Connecting:", errc)
    except requests.exceptions.Timeout as errt:
        print("Timeout Error:", errt)
    except requests.exceptions.RequestException as err:
        print("Oops: Something Else", err)

    # parse the json response
    global MASTER_DICT
    id_list = json_extract(response.json(), "ID")
    url_list = json_extract(response.json(), "url")
    h1_url_list = [i for i in url_list if "hackerone" in i]
    MASTER_DICT = dict(zip(id_list, h1_url_list))
    print("done polling the NVD\n")


def tweet_cves():
    """
    This function updates the bot's Twitter timeline with discovered CVEs
    :return: It has no return value
    """
    print("printing discovered CVEs here:\n")
    for cve, h1_url in MASTER_DICT.items():
        tweet = (
            cve
            + " reported via @Hacker0x01 has been published: "
            + SITE_URL
            + cve
            + "\r\n\r\n"
            + h1_url
        )
        try:
            twitta.update_status(tweet)
            print(tweet + "\n\n" + "-------------------" + "\n")
            sleep(1)
        except tweepy.errors.HTTPException as err:
            print("Twitter error: ", err.response.text)


if __name__ == "__main__":
    while True:
        try:
            poll_nvd()
            tweet_cves()
            print("\ndone")
        except Exception as exc:
            print(exc)
        # check every hour
        sleep(3600)
