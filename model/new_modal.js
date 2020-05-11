var con = require('../config/connect');

module.exports.getSinglerow=function(table,where, cb)
{
    console.log(where);
    con.connect(function(err){
        if (err) {
            console.log(err);
        }
        var que = "SELECT * FROM "+table+" WHERE "+where;
        // con.query(que, cb);
        console.log(que);
    });
}


//MONTY
module.exports.bulkinsert=function(cols,values,cb)
{
   console.log('bulkinsert:');
   
   
    con.connect(function(err){
        
		var sql = "INSERT INTO user_media (?) VALUES ?";
			con.query(sql, cols, [values]);
	 });
}
