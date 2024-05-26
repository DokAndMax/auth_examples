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
    redirectUri: 'http://localhost:3000',
    usersAccessToken: null,
};
const checkJwt = auth({
    audience: 'https://kpi.eu.auth0.com/api/v2/',
    issuerBaseURL: `https://kpi.eu.auth0.com/`,
});

const checkScopes = requiredScopes('read:current_user');

retrieveUsersAccessToken();

const app = express();
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));

app.get('/', rootController);
app.get('/dashboard', checkJwt, checkScopes, dashboardController);
app.get('/logout', logoutController);
app.post('/api/login', loginController);
app.post('/api/refresh-token', refreshTokenController);

app.listen(port, () => {
    console.log(`Example app listening on port ${port}`);
});

function rootController(req, res, next) {
    res.sendFile(path.join(__dirname + '/index.html'));
}

function dashboardController(req, res, next) {
    const options = {
        uri: `https://${auth0Config.domain}/userinfo`,
        method: 'GET',
        headers: {
            Authorization: `Bearer ${req.auth.token}`
        },
    };

    request(options, (error, response, body) => {
        if(error || response.statusCode === 401) {
            return res.status(401);
        }

        const userinfoResponse = JSON.parse(body);
        return res.json({
            username: userinfoResponse.nickname,
            logout: 'http://localhost:3000/logout'
        });
    });
}

function logoutController (req, res){
    res.redirect('/');
}

function loginController(req, res){
    const { code } = req.body;

    const data = {
        grant_type: 'authorization_code',
        client_id: auth0Config.clientId,
        client_secret: auth0Config.clientSecret,
        code,
        redirect_uri: auth0Config.redirectUri,
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

        res.json({
            accessToken: authResponse.access_token,
            refreshToken: authResponse.refresh_token,
            idToken: authResponse.id_token,
        });
    });
}

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

        res.json({ accessToken: newAccessToken, refreshToken: refreshToken, idToken: authResponse.id_token });
    });
}

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