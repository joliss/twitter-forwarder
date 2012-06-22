express = require("express")
util = require("util")
OAuth = require("oauth").OAuth
gzippo = require('gzippo')

twitterConsumerKey = process.env["TWITTER_CONSUMER_KEY"]
twitterConsumerSecret = process.env["TWITTER_CONSUMER_SECRET"]

cookieMaxAge = 1000*3600*24*30

oauthConsumer = (req) ->
  new OAuth("https://twitter.com/oauth/request_token", "https://twitter.com/oauth/access_token", twitterConsumerKey, twitterConsumerSecret, "1.0A", "http://#{req.headers.host}/sessions/callback", "HMAC-SHA1")

app = express.createServer()

app.configure "development", ->
  app.use express.errorHandler(
    dumpExceptions: true
    showStack: true
  )
  app.use express.logger()

app.configure ->
  app.use express.cookieParser()
  app.use (req, res, next) ->
    unless req.authenticityToken = req.cookies.twfauthenticitytoken
      res.cookie 'twfauthenticitytoken', (req.authenticityToken = Math.random().toString(36).substr(2)),
        path: '/'
        maxAge: cookieMaxAge
    next()
  app.use(gzippo.staticGzip(__dirname + '/public'))
  app.use(gzippo.compress())

app.dynamicHelpers
  loggedIn: (req, res) ->
    loggedIn(req)
  authenticityToken: (req, res) ->
    req.authenticityToken

app.get "/sessions/connect", (req, res) ->
  oauthConsumer(req).getOAuthRequestToken (error, oauthToken, oauthTokenSecret, results) ->
    if error
      res.send "Error getting OAuth request token : " + util.inspect(error), 500
    else
      res.cookie 'twfoauthrequesttoken', oauthToken,
        path: '/'
        maxAge: 1000*3600*24
      res.cookie 'twfoauthrequesttokensecret', oauthTokenSecret,
        path: '/'
        maxAge: 1000*3600*24
      res.redirect "https://twitter.com/oauth/authorize?oauth_token=" + oauthToken

app.get "/sessions/callback", (req, res) ->
  res.clearCookie 'twfoauthrequesttoken',
    path: '/'
  res.clearCookie 'twfoauthrequesttokensecret',
    path: '/'
  oauthConsumer(req).getOAuthAccessToken req.cookies.twfoauthrequesttoken, req.cookies.twfoauthrequesttokensecret, req.query.oauth_verifier, (error, oauthAccessToken, oauthAccessTokenSecret, results) ->
    if error
      res.send "Error getting OAuth access token : " + util.inspect(error) + "[" + oauthAccessToken + "]" + "[" + oauthAccessTokenSecret + "]" + "[" + util.inspect(results) + "]", 500
    else
      res.cookie 'twfoauthaccesstoken', oauthAccessToken,
        path: '/'
        maxAge: cookieMaxAge
      res.cookie 'twfoauthaccesstokensecret', oauthAccessTokenSecret,
        path: '/'
        maxAge: cookieMaxAge
      res.redirect '/'

# TODO: This should probably be POST or DELETE, and/or CSRF protected
app.get "/sessions/signout", (req, res) ->
  for cookie in ['twfoauthrequesttoken', 'twfoauthrequesttokensecret', 'twfoauthaccesstoken', 'twfoauthaccesstokensecret', 'twfauthenticitytoken']
    res.clearCookie cookie,
      path: '/'
  res.redirect '/'

validAuthenticityToken = (req) ->
  throw 'error' unless req.authenticityToken
  req.authenticityToken == \
    (req.headers['x-csrf-token'] || req.query.authenticity_token)

loggedIn = (req) ->
  req.cookies.twfoauthaccesstoken?

app.all /^\/twitter-api\/(.*)/, (req, res, next) ->
  unless validAuthenticityToken(req)
    res.send 'Missing or invalid CSRF authenticity token', 403
    return
  unless req.method.toUpperCase() == 'GET'
    res.send 'Only GET is supported at the moment', 403
    return
  unless loggedIn(req)
    # We would love to proxy anonymously, but there is a rate limit of 150/h
    # against our server IP.
    res.send 'Not logged in', 403
    return
  # Parse URL
  # req.params[0] does not have query strings, so we use originalUrl
  url = req.originalUrl.replace('/twitter-api', '')
  # We could use https for the API, but since Twitter is a bit slow and we are
  # not using any kind of keep-alive, we're keeping the server-to-server
  # communication unencrypted.
  oauthConsumer(req)._performSecureRequest req.cookies.twfoauthaccesstoken, req.cookies.twfoauthaccesstokensecret, req.method, "http://api.twitter.com#{url}", null, null, null, (error, data, response) ->
    if not response
      res.send 500
      return
    for key in ['date', 'content-type', 'x-runtime', 'x-transaction', 'x-transaction-mask', 'x-access-level', 'x-frame-options', 'pragma', 'last-modified', 'cache-control', 'expires', 'vary', 'etag']
      if response.headers[key]
        res.header(key, response.headers[key])
    res.send data, response.statusCode

app.all //, (req, res, next) ->
  # Drop your own application into index.ejs
  res.render 'index.ejs', layout: false

app.listen parseInt(process.env.PORT or 5000)