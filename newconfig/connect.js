var mysql = require('mysql');

module.exports=mysql.createConnection({
  host: "localhost",
  user: "root",
  password: "ekeymark%23",
  database: "keymarket_development_v1"
});