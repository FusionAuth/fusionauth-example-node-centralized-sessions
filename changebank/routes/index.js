//tag::constants[]
const express = require('express');
const router = express.Router();


const {FusionAuthClient} = require('@fusionauth/typescript-client');

const dotenv = require('dotenv');
dotenv.config();

if (!process.env.clientId) {
  console.error('Missing clientId from .env');
  process.exit();
}
if (!process.env.clientSecret) {
  console.error('Missing clientSecret from .env');
  process.exit();
}
if (!process.env.fusionAuthURL) {
  console.error('Missing fusionAuthURL from .env');
  process.exit();
}
if (!process.env.apiKey) {
  console.error('Missing apiKey from .env');
  process.exit();
}
const apiKey = process.env.apiKey;
const clientId = process.env.clientId;
const clientSecret = process.env.clientSecret;
const fusionAuthURL = process.env.fusionAuthURL;

const hostName = 'changebank.local';

const port = 3004;
const title = 'Changebank';

const client = new FusionAuthClient(apiKey, fusionAuthURL);
const loginUrl = fusionAuthURL+'/oauth2/authorize?client_id='+clientId+'&response_type=code&redirect_uri=http%3A%2F%2F'+hostName+'%3A'+port+'%2Foauth-redirect&scope=offline_access%20openid';
const logoutUrl = fusionAuthURL+'/oauth2/logout?client_id='+clientId;
//end::constants[]


const alwaysAllowed = [ "/logout", "/login", "/favicon.ico", "/stylesheets/style.css", "/endsession" ];
const alwaysAllowedPrefix = [ "/oauth-redirect" ];

router.use((req, res, next) => {
  console.log('url:', req.originalUrl);
  if (alwaysAllowed.indexOf(req.originalUrl) > -1 ) {
    // always allow this
    console.log("always allowed1");
    next();
    return;
  }

  for (let i = 0; i < alwaysAllowedPrefix.length; i++) {
    let prefix = alwaysAllowedPrefix[i];
    console.log(prefix);
    if (req.originalUrl.startsWith(prefix)) {
      // always allow this
      console.log("always allowed2");
      next();
      return;
    }
  }

  if (!req.session.refreshTokenId) {
    console.log("no refresh token");
    res.redirect(302, "/login");
    return;
  }

  //if (req.session && req.session.refreshTokenId) {
    client.retrieveRefreshTokenById(req.session.refreshTokenId)
    .then(clientResponse => {
      console.log("valid session found");
      // console.log("RT:", JSON.stringify(clientResponse.response.refreshToken, null, 2));
      next();
      return;
    }).catch(clientResponse => {
      console.log("here2 "+ req.originalUrl+ ", "+clientResponse.statusCode + ", " +req.session.refreshTokenId);
      if (clientResponse.statusCode !== 200) {
        //session revoked 
        //res.redirect(302, "/logout");
        console.log("session revoked");
        res.redirect(302, "/logout");
        next();
        return;
      }
    });
  //} else {
    // res.redirect(302, "/login");
  //}
})


//tag::homepageroute[]
/* GET home page. */
router.get('/', function (req, res, next) {

  res.render('index', {user: req.session.user, title: title + ' App', clientId: clientId, logoutUrl: "/logout", loginUrl: loginUrl});
});
//end::homepageroute[]

//tag::loginpageroute[]
/* Login page if we aren't logged in */
router.get('/login', function (req, res, next) {
  res.render('login', {title: title + ' Login', clientId: clientId, loginUrl: loginUrl});
});
//end::loginpageroute[]

//tag::logoutpageroute[]
/* Logout page */
router.get('/logout', function (req, res, next) {
  req.session.user = null;
  res.redirect(302, logoutUrl);
});
//end::logoutpageroute[]

//tag::endsessionroute[]
/* End session for global SSO logout */
router.get('/endsession', function (req, res, next) {
  req.session.user = null;
  res.redirect(302, "/login");
});
//end::endsessionroute[]

//tag::oauthredirectroute[]
/* OAuth return from FusionAuth */
router.get('/oauth-redirect', function (req, res, next) {
  // This code stores the user in a server-side session
  client.exchangeOAuthCodeForAccessToken(req.query.code,
                                         clientId,
                                         clientSecret,
                                         'http://'+hostName+':'+port+'/oauth-redirect')
      .then((response) => {
        const refreshTokenId = response.response.refresh_token_id;
        if (!refreshTokenId) {
           throw new Error('No refresh token found, did you request the offline_access scope?');
        }
        req.session.refreshTokenId = refreshTokenId;
        return client.retrieveUserUsingJWT(response.response.access_token);
      })
      .then((response) => {
        console.log(response.response);
        req.session.user = response.response.user;
        return response;
      })
      .then((response) => {
        res.redirect(302, '/');
      }).catch((err) => {console.log("in error"); console.error(JSON.stringify(err));});
});
//end::oauthredirectroute[]

module.exports = router;
