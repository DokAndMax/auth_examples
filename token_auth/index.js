const express = require('express');
const bodyParser = require('body-parser');
const request = require('request');
const fs = require('fs');
const path = require('path');
const { auth, requiredScopes } = require('express-oauth2-jwt-bearer');

const port = 3000;
const auth0Config = {
    domain: 'kpi.eu.auth0.com',
    clientId: 'JIvCO5c2IBHlAe2patn6l6q5H35qxti0',
    clientSecret: 'ZRF8Op0tWM36p1_hxXTU-B0K_Gq_-eAVtlrQpY24CasYiDmcXBhNS6IJMNcz1EgB',
    audience: 'https://kpi.eu.auth0.com/api/v2/',
    usersAccessToken: null,
};
const checkJwt = auth({
    audience: 'https://kpi.eu.auth0.com/api/v2/',
    issuerBaseURL: `https://kpi.eu.auth0.com/`,
});

const checkScopes = requiredScopes('read:current_user');

retrieveUsersAccessToken();

class Session {
    #sessions = {};

    constructor() {
        try {
            this.#sessions = fs.readFileSync('./sessions.json', 'utf8');
            this.#sessions = JSON.parse(this.#sessions.trim());
        } catch (e) {
            this.#sessions = {};
        }
    }

    #storeSessions() {
        fs.writeFileSync('./sessions.json', JSON.stringify(this.#sessions), 'utf-8');
    }

    set(key, value = {}) {
        this.#sessions[key] = value;
        this.#storeSessions();
    }

    get(key) {
        return this.#sessions[key];
    }

    destroy(accessToken) {
        delete this.#sessions[accessToken];
        this.#storeSessions();
    }
}

const sessions = new Session();

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/', rootController);
app.get('/dashboard', checkJwt, checkScopes, dashboardController);
app.get('/logout', logoutController);
app.post('/api/login', loginController);
app.post('/api/create-user', createUserController);
app.post('/api/refresh-token', refreshTokenController);

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});

function rootController(req, res, next) {
    res.sendFile(path.join(__dirname + '/index.html'));
};

function dashboardController(req, res, next) {
    return res.json({
        username: sessions.get(req.auth.payload.sub),
        logout: 'http://localhost:3000/logout'
    });
};

function logoutController (req, res){
    res.redirect('/');
};

function loginController(req, res){
    const { username, password } = req.body;

    const data = {
        grant_type: 'http://auth0.com/oauth/grant-type/password-realm',
        username,
        password,
        audience: auth0Config.audience,
        scope: 'offline_access',
        client_id: auth0Config.clientId,
        client_secret: auth0Config.clientSecret,
        realm: 'Username-Password-Authentication'
    };

    const options = {
        uri: `https://${auth0Config.domain}/oauth/token`,
        method: 'POST',
        headers: {
            'content-type': 'application/x-www-form-urlencoded'
        },
        form: data
    };

    request(options, (error, response, body) => {
        if (error) {
            console.error(error);
            return res.status(500).send('Authentication failed');
        }

        const authResponse = JSON.parse(body);
        if (!authResponse.access_token) {
            return res.status(401).send('Authentication failed');
        }

        const userid = parseJwtSub(authResponse.access_token);
        sessions.set(userid, username);

        res.json({ accessToken: authResponse.access_token, refreshToken: authResponse.refresh_token });
    });
};

function createUserController (req, res){
    const { email, password } = req.body;

    const data = {
        email,
        password,
        user_metadata: {},
        blocked: false,
        email_verified: false,
        app_metadata: {},
        picture: 'https://i.imgur.com/pM2DvuM.jpeg',
        connection: 'Username-Password-Authentication'
    };

    const options = {
        uri: `https://${auth0Config.domain}/api/v2/users`,
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'Authorization': `Bearer ${auth0Config.usersAccessToken}`
        },
        json: data
    };

    request(options, (error, response, body) => {
        if (error) {
            console.error(error);
            return res.status(500).send('User creation failed');
        }

        if (response.statusCode !== 201) {
            return res.status(response.statusCode).send(body.message);
        }

        res.json({ message: 'User created successfully' });
    });
};

function refreshTokenController(req, res){
    const refreshToken = req.body.refreshToken;

    if (!refreshToken) {
        return res.status(401).send('Refresh token missing');
    }

    const data = {
        grant_type: 'refresh_token',
        refresh_token: refreshToken,
        client_id: auth0Config.clientId,
        client_secret: auth0Config.clientSecret,
        audience: auth0Config.audience
    };

    const options = {
        uri: `https://${auth0Config.domain}/oauth/token`,
        method: 'POST',
        headers: {
            'content-type': 'application/x-www-form-urlencoded'
        },
        form: data
    };

    request(options, (error, response, body) => {
        if (error) {
            console.error(error);
            return res.status(500).send('Refresh token failed');
        }

        const authResponse = JSON.parse(body);
        if (!authResponse.access_token) {
            return res.status(401).send('Refresh token failed');
        }

        const newAccessToken = authResponse.access_token;

        res.json({ accessToken: newAccessToken, refreshToken: refreshToken });
    });
};

function retrieveUsersAccessToken() {
    const data = {
        grant_type: 'client_credentials',
        client_id: auth0Config.clientId,
        client_secret: auth0Config.clientSecret,
        audience: auth0Config.audience
    };

    const options = {
        uri: `https://${auth0Config.domain}/oauth/token`,
        method: 'POST',
        headers: {
            'content-type': 'application/x-www-form-urlencoded'
        },
        form: data
    };

    request(options, (error, response, body) => {
        if (error) {
            throw new Error(error);
        }

        const authResponse = JSON.parse(body);
        if (!authResponse.access_token) {
            throw new Error('Refresh token failed');
        }

        auth0Config.usersAccessToken = authResponse.access_token;
    });
}

function parseJwtSub(token) {
    if (!token) {
        return null;
    }

    const parts = token.split('.');
    if (parts.length !== 3) {
        return null;
    }

    const decodedPayload = JSON.parse(atob(parts[1]));
    if (!decodedPayload.sub) {
        return null;
    }

    return decodedPayload.sub;
}