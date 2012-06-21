This is a Node.js server acting as an OAuth consumer for the Twitter API. Once
logged in, all calls under /twitter-api/ are reverse-proxied to Twitter.

It uses an authenticity token stored in a cookie to guard against CSRF.

To run, type

```
node install
coffee web.coffee
```

and open http://localhost:5000/ in your browser. Follow the log-in link on the
page you see.
