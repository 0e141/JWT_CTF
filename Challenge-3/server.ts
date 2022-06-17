const express = require('express');
const bodyParser = require("body-parser");
const cookieParser = require('cookie-parser');
const jwtHelper = require("./lib/jwtHelper.ts");
const res = require('express/lib/response');

var app = express();
const port = 8080;

app.use(bodyParser.urlencoded({extended : true}));
app.use(cookieParser());

app.use('/.well-known', express.static('.well-known'))

app.get('/login', (req, res) => {
  res.sendFile('login.html', {
    root: './views/'
  });
});


app.get('/login_failed', (req, res) => {
  res.sendFile('login_failed.html', {
    root: './views/'
  });
});


app.post('/auth', (req, res) => {
  jwtHelper.auth(req, res);
});


app.get('/logout', (req, res) => {
  jwtHelper.logout(req, res);
});


app.get('/dashboard', (req, res) => {
  jwtHelper.validate(req, res);
});


app.all('*', (req, res) => {
  res.redirect("/dashboard");
});


app.listen(port, () => {
  console.log(`Server listening on port ${port}`);
});