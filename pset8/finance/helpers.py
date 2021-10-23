import urllib.request
import json

import requests
import urllib.parse

from flask import redirect, render_template, request, session, url_for
from functools import wraps

class QuoteResponse:
    def __init__(self, error, result):
        self.result = []
        for mapList in result:
            for element in mapList:
                if element == "regularMarketPrice":
                   price = mapList[element]
                elif element == "displayName":
                   displayName = mapList[element]
                elif element == "symbol":
                    symbol = mapList[element]

            self.result.append(QuoteResult(price, displayName, symbol))
        self.error = error


class Response:
    def __init__(self, quoteResponse):
        self.quoteResponse = QuoteResponse(quoteResponse["error"], quoteResponse["result"])

class QuoteResult:
    def __init__(self, regularMarketPrice, displayName, symbol):
        self.symbol = symbol
        self.regularMarketPrice = regularMarketPrice
        self.displayName = displayName

def apology(top="", bottom=""):
    t = str(bottom)
    """Renders message as an apology to user."""
    def escape(s):
        """
        Escape special characters.
        https://github.com/jacebrowning/memegen#special-characters
        """
        for old, new in [("-", "--"), (" ", "-"), ("_", "__"), ("?", "~q"),
            ("%", "~p"), ("#", "~h"), ("/", "~s"), ("\"", "''")]:
            s = s.replace(old, new)
        return s
    return render_template("apology.html", top=escape(top), bottom=escape(t)), bottom

def login_required(f):
    """
    Decorate routes to require login.
    http://flask.pocoo.org/docs/0.11/patterns/viewdecorators/
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if session.get("user_id") is None:
            return redirect(url_for("login", next=request.url))
        return f(*args, **kwargs)
    return decorated_function

def lookup(symbol):
    """Look up quote for symbol."""

    # reject symbol if it starts with caret
    if symbol.startswith("^"):
        return None

    # reject symbol if it contains comma
    if "," in symbol:
        return None

    # query Yahoo for quote
    # http://stackoverflow.com/a/21351911
    try:
        url = "https://query1.finance.yahoo.com/v7/finance/quote?symbols={}".format(symbol)
        webpage = urllib.request.urlopen(url)
        js = webpage.read().decode("utf-8")
        j = json.loads(js)
        quotes = Response(**j)

        if quotes.quoteResponse.error is not None:
            return None
        quote = quotes.quoteResponse.result[0]
    except Exception as e:
        return {
            "name": "parseError of j=" + json.dumps(j),
            "price": 0,
            "symbol": str(e)
        }

    # ensure stock exists
    try:
        price = float(quote.regularMarketPrice)
    except:
        return {
            "name": "priceError",
            "price": 0,
            "symbol": ""
        }

    # return stock's name (as a str), price (as a float), and (uppercased) symbol (as a str)
    return {
        "name": quote.displayName,
        "price": price,
        "symbol": quote.symbol.upper()
    }


def usd(value):
    """Formats value as USD."""
    return "${:,.2f}".format(value)