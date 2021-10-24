import os

from cs50 import SQL
from flask import Flask, flash, jsonify, redirect, render_template, request, session, url_for
from flask_session import Session
from tempfile import mkdtemp
from werkzeug.exceptions import default_exceptions, HTTPException, InternalServerError
from werkzeug.security import check_password_hash, generate_password_hash

from helpers import apology, login_required, lookup, usd

# Configure application
app = Flask(__name__)

# Ensure templates are auto-reloaded
app.config["TEMPLATES_AUTO_RELOAD"] = True

# Ensure responses aren't cached
if app.config["DEBUG"]:
    @app.after_request
    def after_request(response):
        response.headers["Cache-Control"] = "no-cache, no-store, must-revalidate"
        response.headers["Expires"] = 0
        response.headers["Pragma"] = "no-cache"
        return response

# Custom filter
app.jinja_env.filters["usd"] = usd

# Configure session to use filesystem (instead of signed cookies)
app.config["SESSION_FILE_DIR"] = mkdtemp()
app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
Session(app)

# Configure CS50 Library to use SQLite database
db = SQL("sqlite:///finance.db")


@app.route("/")
@login_required
def index():
    """Show portfolio of stocks"""
    portfolio_symbols = db.execute("SELECT shares, symbol \
                                    FROM portfolio WHERE id = :id", \
                                    id=session["user_id"])
    total_cash = 0
    for portfolio_symbol in portfolio_symbols:
        symbol = portfolio_symbol["symbol"]
        shares = portfolio_symbol["shares"]
        global portfolio_shares
        portfolio_shares = shares
        stock = lookup(symbol)
        total = shares * stock["price"]
        total_cash += total
        db.execute("UPDATE portfolio SET price=:price, \
                    total=:total WHERE id=:id AND symbol=:symbol", \
                    price=usd(stock["price"]), \
                    total=usd(total), id=session["user_id"], symbol=symbol)
    updated_cash = db.execute("SELECT cash FROM users \
                               WHERE id=:id", id=session["user_id"])
    total_cash += updated_cash[0]["cash"]
    updated_portfolio = db.execute("SELECT * from portfolio \
                                    WHERE id=:id", id=session["user_id"])

    return render_template("index.html", stocks=updated_portfolio, \
                            cash=usd(updated_cash[0]["cash"]), total= usd(total_cash) )


@app.route("/buy", methods=["GET", "POST"])
@login_required
def buy():
    """Buy shares of stock"""
    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Missing symbol", 400)
        check = lookup(request.form.get("symbol"))
        if not check:
            return apology("Invalid symbol", 400)
        # not nessesary to check shares since form type is number, but cs50 check need it
        if (request.form.get("shares")).isdigit() == False:
            return apology("Enter positive shares", 400)
        cash = db.execute("SELECT cash FROM users WHERE id = :id", id=session["user_id"])
        money = cash[0]["cash"]
        shares = float(request.form.get("shares"))
        price = check["price"]
        symbol=check["symbol"]
        amount = price * shares
        total = amount
        user_id = session["user_id"]
        if money < amount:
            return apology("Can't afford", 400)
        else:
            db.execute("INSERT INTO transactions (user_id, stock_name, symbol, shares, price, total)\
                       VALUES(:user_id, :stock_name, :symbol, :shares, :price, :total)",
                       user_id=user_id, stock_name=check["name"], symbol=symbol,
                       shares=shares, price=price, total=amount)
            balance = money - amount
            db.execute("UPDATE users SET cash = :balance WHERE id = :user_id",
                       balance=balance, user_id=user_id)
            current_share = db.execute("SELECT shares \
                                        FROM portfolio WHERE id = :user_id AND symbol = :symbol", \
                                        user_id=user_id, symbol = symbol)
            if len(current_share) == 0:
                db.execute("INSERT INTO portfolio (id, symbol, shares, price, total)\
                            VALUES(:user_id, :symbol, :shares, :price, :tptal)",
                            user_id = user_id, symbol = symbol, shares = shares, price = price, total = total)
            else:
                db.execute("UPDATE portfolio SET shares =:shares, price=:price, total=:total \
                            WHERE id =:id AND symbol =:symbol", \
                            id=user_id, symbol = symbol, shares = shares+portfolio_shares, price = price, total = total)

            flash("Bought!")
            return redirect("/")
    else:
        return render_template("buy.html")

@app.route("/check", methods=["GET"])
def check():
    """Return true if username available, else false, in JSON format"""
    username = request.args.get("username")
    data_users = db.execute("SELECT username FROM users")
    count = 0
    for user in data_users:
        if (len(username) < 1) or (username == user["username"]):
            count += 1
    if count > 0:
        return jsonify(False)
    else:
        return jsonify(True)


@app.route("/history")
@login_required
def history():
    """Show history of transactions"""
    user_id = session["user_id"]
    transactions = db.execute("SELECT * FROM transactions WHERE user_id = :user_id", user_id=user_id)
    for stock in transactions:
        stock["price"] = usd(stock["price"])
    return render_template("history.html", histories=transactions)



@app.route("/login", methods=["GET", "POST"])
def login():
    """Log user in"""

    # Forget any user_id
    session.clear()

    # User reached route via POST (as by submitting a form via POST)
    if request.method == "POST":

        # Ensure username was submitted
        if not request.form.get("username"):
            return apology("must provide username", 403)

        # Ensure password was submitted
        elif not request.form.get("password"):
            return apology("must provide password", 403)

        # Query database for username
        rows = db.execute("SELECT * FROM users WHERE username = :username",
                          username=request.form.get("username"))

        # Ensure username exists and password is correct
        if len(rows) != 1 or not check_password_hash(rows[0]["hash"], request.form.get("password")):
            return apology("invalid username and/or password", 403)

        # Remember which user has logged in
        session["user_id"] = rows[0]["id"]

        # Redirect user to home page
        return redirect("/")

    # User reached route via GET (as by clicking a link or via redirect)
    else:
        return render_template("login.html")


@app.route("/account", methods=["GET", "POST"])
@login_required
def account():
    """change user's password"""
    user_id = session["user_id"]
    hashPw = db.execute("SELECT hash FROM users WHERE id = :user_id",
                        user_id=user_id)
    if request.method == "POST":
        if not request.form.get("currentPassword"):
            return apology("Missing current password", 400)
        else:
            if not check_password_hash(hashPw[0]["hash"], request.form.get("currentPassword")):
                return apology("Wrong current password!", 400)
            else:
                success = False
                if request.form.get("newPassword") != request.form.get("repeatNewPassword"):
                    return apology("Password does not match!")
                else:
                    pw = request.form.get("newPassword")
                    hash_pw = generate_password_hash(pw)
                    db.execute("UPDATE users SET hash = :hash_pw WHERE id = :user_id",
                               hash_pw=hash_pw, user_id=user_id)
                    success = True
                if success == True:
                    flash("Account changed")
                    return redirect("/")
                else:
                    flash("Nothing changed")
                    return redirect("/")
    else:
        return render_template("account.html")


@app.route("/logout")
def logout():
    """Log user out"""

    # Forget any user_id
    session.clear()

    # Redirect user to login form
    return redirect("/")


@app.route("/quote", methods=["GET", "POST"])
@login_required
def quote():
    """Get stock quote."""

    if request.method == "POST":
        if not request.form.get("symbol"):
            return apology("Missing symbol", 400)
        check = lookup(request.form.get("symbol"))
        if not check:
            return apology("Invalid symbol", 400)
        else:
            check["price"] = usd(check["price"])
            return render_template("quoted.html", stock=check)
    else:
        return render_template("quote.html")


@app.route("/register", methods=["GET", "POST"])
def register():
    """Register user"""

    if request.method == "POST":
        un = request.form.get("username")
        pw = request.form.get("password")
        if not un:
            return apology("You must provide an username!", 400)
        elif not pw:
            return apology("Missing password", 400)
        elif not request.form.get("confirmation"):
            return apology("Password does not match", 400)
        elif pw != request.form.get("confirmation"):
            return apology("Password does not match", 400)
        elif db.execute("SELECT * FROM users WHERE username = :username",
                        username=un):
            return apology("Username already exists", 400)
        hash_pw = generate_password_hash(pw)
        table = db.execute("INSERT INTO users (username, hash) VALUES(:username, :hash)", username=un, hash=hash_pw)
        session["user_id"] = table
        flash("Registered!")
        return redirect("/")
    else:
        return render_template("register.html")


@app.route("/sell", methods=["GET", "POST"])
@login_required
def sell():
    """Sell shares of stock"""
    user_id = session["user_id"]
    current_stocks = db.execute("SELECT symbol FROM transactions WHERE user_id = :user_id GROUP BY symbol", user_id=user_id)

    if request.method == "GET":
        list_symbols = list()
        for symbol in current_stocks:
            shares_info = db.execute("SELECT SUM(shares) AS shares_sum FROM transactions\
                                    WHERE user_id = :user_id GROUP BY symbol HAVING symbol = :symbol", user_id=user_id, symbol=symbol["symbol"].upper())
            current_shares = shares_info[0]
            if shares_info[0]["shares_sum"]:
                list_symbols.append(symbol["symbol"])
        return render_template("sell.html", list_symbols=list_symbols)
    else:
        if not request.form.get("symbol"):
            return apology("MISSING SYMBOL", 400)
        if not request.form.get("shares"):
            return apology("MISSING SHARES", 400)
        sell_symbol = request.form.get("symbol").upper()
        sell_shares = float(request.form.get("shares"))
        shares_info = db.execute("SELECT SUM(shares) AS shares_sum FROM transactions\
                                    WHERE user_id = :user_id GROUP BY symbol HAVING symbol = :symbol", user_id=user_id, symbol=sell_symbol.upper())
        if shares_info[0]["shares_sum"] < sell_shares:
            return apology("TOO MANY SHARES", 400)
        #return apology(json.dumps(shares_info), 400)
        else:
            check = lookup(sell_symbol)
            price = check["price"]
            money = -sell_shares * price
            total = sell_shares * price
            cash = db.execute("SELECT cash FROM users WHERE id = :id", id=user_id)
            balance = cash[0]["cash"] - money
            db.execute("INSERT INTO transactions (user_id, stock_name, symbol, shares, price, total)\
                        VALUES(:user_id, :stock_name, :symbol, :shares, :price, :total)",
                       user_id=user_id, stock_name=check["name"], symbol=sell_symbol, shares=-sell_shares, price=price, total=money)
            db.execute("UPDATE users SET cash = :balance WHERE id = :user_id", balance=balance, user_id=user_id)

            current_share = db.execute("SELECT shares \
                                        FROM portfolio WHERE id = :user_id AND symbol = :symbol", \
                                        user_id=user_id, symbol = sell_symbol)
            if len(current_share) != 0 and portfolio_shares > sell_shares:
                db.execute("UPDATE portfolio SET shares =:shares, price=:price, total=:total \
                            WHERE id =:id AND symbol =:symbol", \
                            id=user_id, symbol = sell_symbol, shares = portfolio_shares - sell_shares, price = price, total = total)
            else:
                db.execute("DELETE FROM portfolio (id, symbol, shares, price, total)\
                            WHERE id =:id AND symbol =:symbol",
                            user_id = user_id, symbol = sell_symbol, shares = sell_shares, price = price, total = total)
            flash("Sold")
            return redirect("/")


def errorhandler(e):
    """Handle error"""
    if not isinstance(e, HTTPException):
        e = InternalServerError()
    return apology(e.name, e.code)
    #response.raise_for_status()


# Listen for errors
for code in default_exceptions:
    app.errorhandler(code)(errorhandler)



