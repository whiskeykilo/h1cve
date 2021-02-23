import tweepy
import requests
import json
import os
from datetime import datetime, timedelta
from dotenv import load_dotenv
from extract import json_extract
from time import sleep

# get environment variables from .env
load_dotenv()

# try the OS variables just in case (for Heroku)
consumer_key = os.getenv("API_KEY")
consumer_secret_key = os.getenv("API_SECRET_KEY")
access_token = os.getenv("ACCESS_TOKEN")
access_token_secret = os.getenv("ACCESS_TOKEN_SECRET")

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


def get_cves():
    """
    This function pulls CVEs from NVD in the specified time period and order
    :return: It returns a list
    """
    response = requests.get(api_url, params=params)
    global id_list
    id_list = json_extract(response.json(), "ID")


def tweet_cves():
    """
    This function updates the Twitter timeline with discovered CVEs
    :return: It has no return value
    """
    for i in id_list:
        tweet = i + " reported via @Hacker0x01 has been published: " + site_url + i
        try:
            twitta.update_status(tweet)
            sleep(5)
        except tweepy.error.TweepError:
            pass


if __name__ == "__main__":
    get_cves()
    tweet_cves()