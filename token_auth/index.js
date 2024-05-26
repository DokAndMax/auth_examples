const express = require('express');
const bodyParser = require('body-parser');
const request = require('request');
const fs = require('fs');
const path = require('path');

const port = 3000;
const SESSION_KEY = 'Authorization';
const auth0Config = {
    domain: 'kpi.eu.auth0.com',
    clientId: 'JIvCO5c2IBHlAe2patn6l6q5H35qxti0',
    clientSecret: 'ZRF8Op0tWM36p1_hxXTU-B0K_Gq_-eAVtlrQpY24CasYiDmcXBhNS6IJMNcz1EgB',
    audience: 'https://kpi.eu.auth0.com/api/v2/',
    usersAccessToken: null,
};

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
const refreshTokens = new Session();

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(checkAuthentication);

app.get('/', rootController);
app.get('/logout', logoutController);
app.post('/api/login', loginController);
app.post('/api/create-user', createUserController);
app.post('/api/refresh-token', refreshTokenController);

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});

function checkAuthentication (req, res, next) {
    const authHeader = req.get(SESSION_KEY);
    const [scheme, accessToken] = authHeader ? authHeader.split(' ') : [];

    req.session = {};

    if (scheme?.toLowerCase() === 'bearer' && accessToken) {
        const session = sessions.get(accessToken);
        if (session) {
            req.session = session;
            req.accessToken = accessToken;
        }
    }

    next();
};

function rootController(req, res) {
    if (req.session.username) {
        return res.json({
            username: req.session.username,
            logout: 'http://localhost:3000/logout'
        });
    }
    res.sendFile(path.join(__dirname + '/index.html'));
};

function logoutController (req, res){
    sessions.destroy(req.accessToken);
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

        req.session.refreshToken = authResponse.refresh_token;
        req.session.username = username;

        sessions.set(authResponse.access_token, req.session);
        refreshTokens.set(authResponse.refresh_token, authResponse.access_token);

        res.json({ accessToken: authResponse.access_token, refreshToken: req.session.refreshToken });
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

        const oldAccessToken = refreshTokens.get(refreshToken);
        const newAccessToken = authResponse.access_token;
        const session = sessions.get(oldAccessToken);
        sessions.destroy(oldAccessToken);
        sessions.set(newAccessToken, session);
        refreshTokens.set(refreshToken, newAccessToken);

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