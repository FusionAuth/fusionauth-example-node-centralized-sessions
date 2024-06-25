const alwaysAllowed = [ "/logout", "/login", "/favicon.ico", "/stylesheets/style.css", "/endsession" ];
const alwaysAllowedPrefix = [ "/oauth-redirect" ];

const redirectFunction = ((req, res, next) => {
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
});

module.exports = redirectFunction;
