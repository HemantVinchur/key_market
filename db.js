var mysql = require('mysql');
var connection = mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "ekeymark%23",
  database: "keymarket_development"
});

connection.connect(function(err) {
    if (err) throw err;
});

module.exports = connection;