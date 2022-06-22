const express = require('express');
const app = express();
const mysql = require('mysql');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const cookieParser = require("cookie-parser");
const session = require("express-session");
const jwt = require("jsonwebtoken")

// connects to the data base to access date in table
const db = mysql.createPool({
    host: 'localhost',
    user: 'root',
    password: '',
    database: 'cavdatabase',
})
app.use(cors({
    origin: ["http://localhost:3000"],
    methods: ["GET", "POST"],
    credentials: true

}));

app.use(cookieParser())
app.use(session(
    {
        key: "userId",
        secret: "subscribe",
        resave: false,
        saveUninitialized: false,
        cookie: {
            expires: 60 * 60 * 1,
        }
    }
))
app.use(express.json())
app.use(bodyParser.urlencoded({ extended: true }))

app.get('/', (req, res) => {

    res.send("server is running")

})

// this part is for user response and request authentication 
const verifyJWT = (req, res, next) => {
    const token = req.headers["x-access-token"]

    if (!token) {
        res.send("we need a token,please give it to us next time")
    } else {
        jwt.verify(token, "jwtSecret", (err, decoded) => {
            if (err) {
                res.json({ auth: false, message: "you failed to authenticate" })
            } else {
                req.userId = decoded.id;
                next();
            }
        })
    }
}
app.get('/api/isUserAuth', verifyJWT, (req, res) => {
    res.send(req.session.user.name)
})

app.get('/api/userconfirm', (req, res) => {
    if (req.session.user) {
        res.send({ loggedIn: true, user: req.session.user })
    } else {
        res.send({ loggedIn: false, user: req.session.user })
    }
})
app.post('/api/userconfirm', (req, res) => {


    const email = req.body.email
    const password = req.body.password
    const sqlSelect = 'SELECT * FROM users WHERE email = ?';



    db.query(sqlSelect, [email], (err, result) => {
        if (err) {
            res.send({ err: err })
        }
        if (result.length > 0) {
            bcrypt.compare(password, result[0].password, (error, response) => {
                if (response) {
                    req.session.user = result
                    const name = result[0].name
                    const id = result[0].id
                    const token = jwt.sign({ id }, "jwtsecret", {
                        expiresIn: 3000,
                    })

                    res.json({ auth: true, token: token, name: name });

                } else {
                    res.send({ message: "wrong username/password combination" });
                }

            })
        } else {
            res.send({ message: "user does not exist" });
        }

    }
    );

});


app.post("/api/userreg", (req, res) => {
    const name = req.body.name
    const email = req.body.email
    const password = req.body.password
    const phone = req.body.phone
    const sqlInsert = "INSERT INTO users (name, email, password,phone) VALUES (?,?,?,?)";

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.log(err)
            res.send({ message: "0" })
        } else {
            db.query(sqlInsert, [name, email, hash, phone], (err, result) => {
                if (err) {
                    console.log(err);
                    res.send({ message: "0" })
                } else {
                    res.send({ message: '1' })
                }

            });

        }

    })
})


// this part is for admin request and response authentication

app.get('/api/adminconfirm', (req, res) => {
    if (req.session.user) {
        res.send({ loggedIn: true, user: req.session.user })
    } else {
        res.send({ loggedIn: false, user: req.session.user })
    }
})
app.post('/api/adminconfirm', (req, res) => {


    const email = req.body.email
    const password = req.body.password
    const sqlSelect = 'SELECT * FROM admins WHERE email = ?';



    db.query(sqlSelect, [email], (err, result) => {
        if (err) {
            res.send({ err: err })
        }
        if (result.length > 0) {
            bcrypt.compare(password, result[0].password, (error, response) => {
                if (response) {
                    req.session.user = result
                    const name = result[0].name
                    const id = result[0].id
                    const token = jwt.sign({ id }, "jwtsecret", {
                        expiresIn: 3000,
                    })

                    res.json({ auth: true, token: token, name: name });

                } else {
                    res.send({ message: "wrong username/password combination" });
                }

            })
        } else {
            res.send({ message: "admin does not exist" });
        }

    }
    );

});


app.post("/api/adminreg", (req, res) => {
    const name = req.body.name
    const email = req.body.email
    const password = req.body.password
    const sqlInsert = "INSERT INTO admins (name, email, password) VALUES (?,?,?)";

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.log(err)
            res.send({ message: "0" })
        } else {
            db.query(sqlInsert, [name, email, hash], (err, result) => {
                if (err) {
                    console.log(err);
                    res.send({ message: "0" })
                } else {
                    res.send({ message: '1' })
                }

            });

        }

    })
})



// this part is for field officer request and response authentication 

app.get('/api/fieldofficerconfirm', (req, res) => {
    if (req.session.user) {
        res.send({ loggedIn: true, user: req.session.user })
    } else {
        res.send({ loggedIn: false, user: req.session.user })
    }
})
app.post('/api/fieldofficerconfirm', (req, res) => {


    const email = req.body.email
    const password = req.body.password
    const sqlSelect = 'SELECT * FROM fieldofficers WHERE email = ?';



    db.query(sqlSelect, [email], (err, result) => {
        if (err) {
            res.send({ err: err })
        }
        if (result.length > 0) {
            bcrypt.compare(password, result[0].password, (error, response) => {
                if (response) {
                    req.session.user = result
                    const name = result[0].name
                    const id = result[0].id
                    const token = jwt.sign({ id }, "jwtsecret", {
                        expiresIn: 3000,
                    })

                    res.json({ auth: true, token: token, name: name });

                } else {
                    res.send({ message: "wrong username/password combination" });
                }

            })
        } else {
            res.send({ message: "user does not exist" });
        }

    }
    );

});


app.post("/api/fieldofficerreg", (req, res) => {
    const name = req.body.name
    const email = req.body.email
    const password = req.body.password
    const phone = req.body.phone
    const sqlInsert = "INSERT INTO fieldofficers (name, email, password,phone) VALUES (?,?,?,?)";

    bcrypt.hash(password, 10, (err, hash) => {
        if (err) {
            console.log(err)
            res.send({ message: "0" })
        } else {
            db.query(sqlInsert, [name, email, hash, phone], (err, result) => {
                if (err) {
                    console.log(err);
                    res.send({ message: "0" })
                } else {
                    res.send({ message: '1' })
                }

            });

        }

    })
})




app.listen(3001, () => {
    console.log("running on port 3001")
})