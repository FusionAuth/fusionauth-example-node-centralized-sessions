//tag::top[]
import FusionAuthClient from "@fusionauth/typescript-client";
import express from 'express';
import cookieParser from 'cookie-parser';
import pkceChallenge from 'pkce-challenge';
import { GetPublicKeyOrSecret, verify } from 'jsonwebtoken';
import jwksClient, { RsaSigningKey } from 'jwks-rsa';
import * as path from 'path';

// Add environment variables
import * as dotenv from "dotenv";
dotenv.config();

const app = express();
const port = 8081; // default port to listen
const hostname = 'changebankforum.local'; // default port to listen

if (!process.env.clientId) {
  console.error('Missing clientId from .env');
  process.exit();
}
if (!process.env.clientSecret) {
  console.error('Missing clientSecret from .env');
  process.exit();
}
if (!process.env.fusionAuthURL) {
  console.error('Missing clientSecret from .env');
  process.exit();
}
const clientId = process.env.clientId;
const clientSecret = process.env.clientSecret;
const fusionAuthURL = process.env.fusionAuthURL;

// Validate the token signature, make sure it wasn't expired
const validateUser = async (userTokenCookie: { access_token: string }) => {
  // Make sure the user is authenticated.
  if (!userTokenCookie || !userTokenCookie?.access_token) {
    return false;
  }
  try {
    let decodedFromJwt;
    await verify(userTokenCookie.access_token, await getKey, undefined, (err, decoded) => {
      decodedFromJwt = decoded;
    });
    return decodedFromJwt;
  } catch (err) {
    console.error(err);
    return false;
  }
}


const getKey: GetPublicKeyOrSecret = async (header, callback) => {
  const jwks = jwksClient({
    jwksUri: `${fusionAuthURL}/.well-known/jwks.json`
  });
  const key = await jwks.getSigningKey(header.kid) as RsaSigningKey;
  var signingKey = key?.getPublicKey() || key?.rsaPublicKey;
  callback(null, signingKey);
}

//Cookies
const userSession = 'userSession';
const userToken = 'userToken';
const userDetails = 'userDetails'; //Non Http-Only with user info (not trusted)

const client = new FusionAuthClient('noapikeyneeded', fusionAuthURL);

app.use(cookieParser());
/** Decode Form URL Encoded data */
app.use(express.urlencoded());

//end::top[]

// Static Files
//tag::static[]
app.use('/static', express.static(path.join(__dirname, '../static/')));
//end::static[]

//tag::homepage[]
app.get("/", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (await validateUser(userTokenCookie)) {
    res.redirect(302, '/forum');
  } else {
    const stateValue = Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15) + Math.random().toString(36).substring(2, 15);
    const pkcePair = await pkceChallenge();
    res.cookie(userSession, { stateValue, verifier: pkcePair.code_verifier, challenge: pkcePair.code_challenge }, { httpOnly: true });

    res.sendFile(path.join(__dirname, '../templates/home.html'));
  }
});
//end::homepage[]

//tag::login[]
app.get('/login', (req, res, next) => {
  const userSessionCookie = req.cookies[userSession];

  // Cookie was cleared, just send back (hacky way)
  if (!userSessionCookie?.stateValue || !userSessionCookie?.challenge) {
    res.redirect(302, '/');
  }

  res.redirect(302, `${fusionAuthURL}/oauth2/authorize?client_id=${clientId}&response_type=code&redirect_uri=http://${hostname}:${port}/oauth-redirect&state=${userSessionCookie?.stateValue}&code_challenge=${userSessionCookie?.challenge}&code_challenge_method=S256`)
});
//end::login[]

//tag::oauth-redirect[]
app.get('/oauth-redirect', async (req, res, next) => {
  // Capture query params
  const stateFromFusionAuth = `${req.query?.state}`;
  const authCode = `${req.query?.code}`;

  // Validate cookie state matches FusionAuth's returned state
  const userSessionCookie = req.cookies[userSession];
  if (stateFromFusionAuth !== userSessionCookie?.stateValue) {
    console.log("State doesn't match. uh-oh.");
    console.log("Saw: " + stateFromFusionAuth + ", but expected: " + userSessionCookie?.stateValue);
    res.redirect(302, '/');
    return;
  }

  try {
    // Exchange Auth Code and Verifier for Access Token
    const accessToken = (await client.exchangeOAuthCodeForAccessTokenUsingPKCE(authCode,
      clientId,
      clientSecret,
      `http://${hostname}:${port}/oauth-redirect`,
      userSessionCookie.verifier)).response;

    if (!accessToken.access_token) {
      console.error('Failed to get Access Token')
      return;
    }
    res.cookie(userToken, accessToken, { httpOnly: true })

    // Exchange Access Token for User
    const userResponse = (await client.retrieveUserUsingJWT(accessToken.access_token)).response;
    if (!userResponse?.user) {
      console.error('Failed to get User from access token, redirecting home.');
      res.redirect(302, '/');
    }
    res.cookie(userDetails, userResponse.user);

    res.redirect(302, '/forum');
  } catch (err: any) {
    console.error(err);
    res.status(err?.statusCode || 500).json(JSON.stringify({
      error: err
    }))
  }
});
//end::oauth-redirect[]

app.get("/forum", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.redirect(302, '/');
  } else {
    res.sendFile(path.join(__dirname, '../templates/forum.html'));
  }
});

app.get("/latest-posts", async (req, res) => {
  const userTokenCookie = req.cookies[userToken];
  if (!await validateUser(userTokenCookie)) {
    res.redirect(302, '/');
  } else {
    res.sendFile(path.join(__dirname, '../templates/latest-posts.html'));
  }
});

//tag::logout[]
app.get('/logout', (req, res, next) => {
  res.redirect(302, `${fusionAuthURL}/oauth2/logout?client_id=${clientId}`);
});
//end::logout[]

app.get('/endsession', (req, res, next) => {
  console.log('Ending session...')
  res.clearCookie(userSession);
  res.clearCookie(userToken);
  res.clearCookie(userDetails);

  res.redirect(302, '/')
});

// start the Express server
//tag::app[]
app.listen(port, () => {
  console.log(`server started at http://${hostname}:${port}`);
});
//end::app[]
