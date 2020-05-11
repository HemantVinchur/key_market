var mysql = require('mysql');

module.exports = mysql.createConnection({
    host: "localhost",
    user: "root",
    password: "linuxconfig.org",
    database: "keymarket_development"
});