import auth0 from "auth0-js";

const REDIRECT_ON_LOGIN = "redirect_on_login";

let _idToken = null;
let _accessToken = null;
let _scopes = null;
let _expiresAt = null;

export default class Auth {
  constructor(history, domain, clientID, audience, redirectUri) {
    this.history = history; // passing React Router's history will help Auth to perform redirects.
    this.userProfile = null;
    this.requestedScopes = "openid profile email read:courses";
    this.auth0 = new auth0.WebAuth({
      domain: domain,
      clientID: clientID,
      audience: audience,
      redirectUri: redirectUri,
      /**
       * id token: JWT token to authenticate the user when they login
       * token: Access token so the user can make API calls
       */
      responseType: "token id_token",
      scope: this.requestedScopes,
    });
  }
  /**
   * handle login by using authorize method of auth0
   */
  login = () => {
    localStorage.setItem(
      REDIRECT_ON_LOGIN,
      JSON.stringify(this.history.location)
    );
    // will redirect the browser to Auth0 login page
    this.auth0.authorize();
  };

  /**
   * handles authentication using parseHash method of auth0.
   * parseHash return err and authResult.
   * check if expected value are in authResult.
   * if YES,then setSession and redirect to '/'
   * else if error, then redirect to '/' and log error message.
   */
  handleAuthentication = (history) => {
    this.auth0.parseHash((err, authResult) => {
      if (authResult && authResult.accessToken && authResult.idToken) {
        this.setSession(authResult);
        const redirectLocation =
          localStorage.getItem(REDIRECT_ON_LOGIN) === "undefined"
            ? "/"
            : JSON.parse(localStorage.getItem(REDIRECT_ON_LOGIN));
        history.push(redirectLocation);
      } else {
        history.push("/");
        alert(`Error: ${err.error}. Check the console for further details.`);
        console.log(err);
      }
      localStorage.removeItem(REDIRECT_ON_LOGIN);
    });
  };

  setSession = (authResult) => {
    /**
     * authResult.expiresIn contains JWT expiration in seconds
     * multiply it by 1000 to convert into ms.
     * add current unix epoch time (new Date().getTime()) to get the unix epoch time when token will expire
     */
    _expiresAt = authResult.expiresIn * 1000 + new Date().getTime(); // set the time that the access tokes will expire

    /**
     * If there is a value in the `scopes` params from authResult,
     * use it to set scopes in the session for the use. Otherwise
     * use the scope as requested. If no axopes are requestedm set it to nothing
     */
    _scopes = authResult.scope || this.requestedScopes || "";

    _accessToken = authResult.accessToken;
    _idToken = authResult.idToken;
    this.refreshToken();
  };

  /**
   *
   * check if user is authenticated
   */
  isAuthenticated() {
    return new Date().getTime() < _expiresAt;
  }

  /**
   * handles logout
   */
  logout = () => {
    this.auth0.logout({
      clientID: process.env.REACT_APP_AUTH0_CLIENT_ID,
      returnTo: "http://localhost:3000",
    });
  };
  /**
   *
   * @returns access token
   */
  getAccessToken = () => {
    if (!!!_accessToken) {
      throw new Error("No access token found.");
    }
    return _accessToken;
  };
  /**
   *
   * @param {*} cb
   * @returns user profile
   */
  getProfile = (cb) => {
    if (this.userProfile) return cb(this.userProfile);
    this.auth0.client.userInfo(this.getAccessToken(), (err, profile) => {
      if (profile) this.userProfile = profile;
      cb(profile, err);
    });
  };
  /**
   * check if user has scopes
   * @param {*} scopes
   * @returns boolean
   */
  userHasScopes(scopes) {
    const grantedScopes = (_scopes || "").split(" ");
    console.log(scopes.every((scope) => grantedScopes.includes(scope)));
    return scopes.every((scope) => grantedScopes.includes(scope));
  }

  /**
   *
   * @param {*} cb
   * renews access token
   */
  renewToken(cb) {
    this.auth0.checkSession({}, (err, result) => {
      if (err) {
        console.log(`Error - ${err.error} - ${err.error_description}.`);
      } else {
        this.setSession(result);
      }
      if (cb) cb(err, result);
    });
  }
  /**
   * refresh token when current token expires
   */
  refreshToken() {
    const delay = _expiresAt - Date.now();
    if (delay > 0) setTimeout(() => this.renewToken(), delay);
  }
}
