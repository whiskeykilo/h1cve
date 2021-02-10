import requests  # Requests is a http library written for humans
import json  # JSON is a Python inbuilt library that makes it easy to work with json.
import tweepy  # Tweepy is a Twitter API wrapper
import time


# Visit apps.twitter.com to get the following variables
consumer_key = "consumer_key"
consumer_secret = "consumer_secret"
access_token = "access_token"
access_token_secret = "access_token_secret"


# Twitter requires oAuth2 to access its API
auth = tweepy.OAuthHandler(consumer_key, consumer_secret)
auth.set_access_token(access_token, access_token_secret)
api = tweepy.API(auth)  # This creates an object called api


# National Vulnerability Database (NVD) API
api_url = "https://services.nvd.nist.gov/rest/json/cves/1.0"


def get_cves():
    """This function gets new CVEs from the NVD API
    :return: It returns a dictionary object
    """
    headers = {"X-Mashape-Host": api_url}
    response = requests.get(api_url, headers=headers)
    json_converted_dictionary = json.loads(response.content.decode())
    json_converted_dictionary = (
        json_converted_dictionary["cve"] + " --" + json_converted_dictionary["author"]
    )
    return json_converted_dictionary


def tweet_cve():
    """This function tweets a new CVE.
    It tweets CVEs from the get_cves() function.
    :return: It has no return value
    """
    for i in range(1, 10):
        cve = get_cves()
        time.sleep(30)
        try:
            api.update_status(cve)  # This method is accessed in tweepy
            print("Done")
        except tweepy.error.TweepError:
            pass


if __name__ == "__main__":
    tweet_cve()