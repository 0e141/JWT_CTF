const jwt = require("jsonwebtoken");
const fs = require("fs");

const secret = "KvwF&!rHuVhVsPv!HwjWGciGirUxW^SmEk@J#zy2NGWd6rb@yTv&EvWQP55j8F2He*zpoBWt6$3XJ^FtDsnfQhAJdKLZt^TdsSRvi&*iNzU4&RSGY^3DtN!SpZmecota";
const user = { name: "user", pwd: "password" };
const allowedIdsFile = "./allowedIds.json";

function auth(req, res){
    try {
        let reqUName = req["body"]["username"];
        let reqPwd = req["body"]["password"];

        if (reqUName && reqUName === user["name"] && reqPwd && reqPwd === user["pwd"]) {
            successfulLogin(req, res)
            return res.redirect("/dashboard");
        }
    }
    catch (e) {

    }

    return res.redirect("/login_failed");
}


function successfulLogin(req, res) {
    let token = genToken();

    res.cookie("token", token, { maxAge: 86400000, httpOnly: true });
}


function genToken() {
    let uuid = Math.floor((Math.random() * 100000) + 1);
    let allowedIds = [];

    if (fs.existsSync(allowedIdsFile)) {
        let dataIn = fs.readFileSync(allowedIdsFile);

        try {
            allowedIds = JSON.parse(dataIn);
        }
        catch (e) {

        }
    }

    allowedIds.push(uuid);
    let dataOut = JSON.stringify(allowedIds);

    fs.writeFile(allowedIdsFile, dataOut, function (err) {
        if (err) {
            console.log(err.message);
            return;
        }
    });

    let token = jwt.sign({
        auth: uuid,
        text: "Looks secure to me!",
        role: "User",
        exp: Math.floor(Date.now() / 1000) + (60 * 60 * 24)
    }, secret);

    return token;
}


async function validate(req, res) {
    let token = req.cookies["token"];

    if (token) {
        let decodedToken;
        let allowedIds = [];

        await new Promise((resolve) =>
        jwt.verify(token, secret, function (err, payload) {
            if (err) {
                decodedToken = null;
            }
            else {
                decodedToken = payload;
            }
            resolve(null);
        }));

        if (decodedToken) {
            if (fs.existsSync(allowedIdsFile)) {
                let dataIn = fs.readFileSync(allowedIdsFile);

                try {
                    allowedIds = JSON.parse(dataIn);
                }
                catch (e) {

                }

                if (allowedIds.includes(decodedToken["auth"])) {
                    if (decodedToken["role"] === "User") {
                        return res.sendFile("user.html", {
                            root: "./views/"
                        });
                    }
                    else if (decodedToken["role"] === "Admin") {
                        return res.sendFile("admin.html", {
                            root: "./views/"
                        });
                    }
                }
            }
        }
    }

    return res.redirect("/logout");
}


function logout(req, res) {
    let token = req.cookies["token"];

    if (token) {
        res.cookie("token", "", { maxAge: 0 });
        let decodedToken;

        try {
            decodedToken = jwt.decode(token);
        }
        catch (e) {
            decodedToken = null;
        }

        if (decodedToken) {
            let allowedIds = [];

            if (fs.existsSync(allowedIdsFile)) {
                let dataIn = fs.readFileSync(allowedIdsFile);

                try {
                    allowedIds = JSON.parse(dataIn);
                }
                catch (e) {

                }

                let uuid = decodedToken["auth"];
                let index = allowedIds.indexOf(uuid);

                if (index > -1) {
                    allowedIds.splice(index, 1);
                }

                let dataOut = JSON.stringify(allowedIds);

                fs.writeFile(allowedIdsFile, dataOut, function (err) {
                    if (err) {
                        console.log(err.message);
                        return;
                    }
                });
            }
        }
    }

    return res.redirect("/login");
}


module.exports = {
    auth: auth,
    validate: validate,
    logout: logout
}