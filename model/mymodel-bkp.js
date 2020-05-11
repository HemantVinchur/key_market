    
var con = require('../config/connect');
var base_url = "http://13.232.102.101/admin/";
var fs = require('fs');
var nodemailer = require('nodemailer');
const sendmail = require('sendmail')();
var _ = require('lodash');
var request = require('request');
 var googleTranslate = require('google-translate')('AIzaSyB0aTR_q7mn-eif8W-di1ZqIXYOHO5Wr78');// var fcm = require('fcm-notification');
   
var transporter = nodemailer.createTransport({
                host: 'ssl://smtp.googlemail.com',
                port: '465',
                secure: 'false', 
                auth: {
                    user: 'samyotechindore@gmail.com',
                    pass: 'Sam%123yo'
                }
            });

module.exports.getSingleRowOrderBy=function(table,user_pub_id, cb)
{
    con.connect(function(err){
        if (err) {
            console.log(err);
        }
        // var que = "SELECT *,CONCAT( '"+base_url+"',  chat.media) AS media,CONCAT( '"+base_url+"',  chat.thumb) AS thumb,CONCAT( '"+base_url+"',  user.profile_image) AS userImage,user.name AS userName FROM "+table+" join user on user.pub_id = chat.user_pub_id || chat.user_pub_id_receiver WHERE chat.user_pub_id_receiver='"+user_pub_id+"' || chat.user_pub_id='"+user_pub_id+"' order by id desc";
       var que = "SELECT *,CONCAT( '"+base_url+"',  user.profile_image) AS userImage,user.user_name,user.name AS userName FROM "+table+" join user on user.pub_id = chat.user_pub_id || chat.user_pub_id_receiver WHERE chat.user_pub_id_receiver='"+user_pub_id+"' || chat.user_pub_id='"+user_pub_id+"' order by id desc";
       
        con.query(que, cb);
    });
}


module.exports.getSearchDataWithCatWithoutTag=function(lat,long,table,where,user_pub_id,distance,cb)
{
   
  var edate = (new Date()).valueOf().toString();
  var curdate = edate.substr(0, 10);
  var pastdate = curdate-86400;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';
  

    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  updated_at between '"+pastdate+"' and '"+curdate+"' and  access ='1' and ";
    var counter=1;

        for(var k in where){
            if(counter==1)
            {
                que += k+"= '"+where[k]+"'";
            }
            else
            {
                que += " AND "+k+"= '"+where[k]+"' ";

            }
            counter++;
        }
        que +=" having distance <="+distance+ " order by distance"   
    con.query(que, cb);
}

module.exports.getSearchDataWithoutTag=function(lat,long,table,where,user_pub_id,distance,cb)
{
  var edate = (new Date()).valueOf().toString();
  var curdate = edate.substr(0, 10);
  var pastdate = curdate-86400;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';

    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  updated_at between '"+pastdate+"' and '"+curdate+"' and  access ='1' and ";
    var counter=1;

        for(var k in where){
            if(counter==1)
            {
                que += k+"= '"+where[k]+"'";
            }
            else
            {
                que += " AND "+k+"= '"+where[k]+"' ";

            }
            counter++;
        }
        que +=" having distance <="+distance+ " order by distance"  
 con.query(que, cb);
}

module.exports.getSearchDataWithoutTagBetween=function(lat,long,table,where,user_pub_id,distance,start_year,end_year,cb)
{
  var edate = (new Date()).valueOf().toString();
  var curdate = edate.substr(0, 10);
  var pastdate = curdate-86400;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';
  console.log(where);


    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  updated_at between '"+pastdate+"' and '"+curdate+"' and  access ='1' and car_year between '"+start_year+"' and '"+end_year+"' and ";
    var counter=1;

        for(var k in where){
            if(counter==1)
            {
                que += k+"= '"+where[k]+"'";
            }
            else
            {
                que += " AND "+k+"= '"+where[k]+"' ";

            }
            counter++;
        }
        que +=" having distance <="+distance+ " order by distance"     
 con.query(que, cb);
}

module.exports.getSearchBetweenPrice=function(lat,long,table,where,user_pub_id,distance,start_price,end_price,cb)
{
  var edate = (new Date()).valueOf().toString();
  var curdate = edate.substr(0, 10);
  var pastdate = curdate-86400;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';
  console.log(where);


    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  updated_at between '"+pastdate+"' and '"+curdate+"' and  access ='1' and price between '"+start_price+"' and '"+end_price+"' and ";
    var counter=1;

        for(var k in where){
            if(counter==1)
            {
                que += k+"= '"+where[k]+"'";
            }
            else
            {
                que += " AND "+k+"= '"+where[k]+"' ";

            }
            counter++;
        }
        que +=" having distance <="+distance+ " order by distance"     
 con.query(que, cb);
}

module.exports.getKMLikesProducts=function(lat,long,table,where,user_pub_id,distance,likes,cb)
{
  var edate = (new Date()).valueOf().toString();
  var curdate = edate.substr(0, 10);
  var pastdate = curdate-86400;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';
  

    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  updated_at between '"+pastdate+"' and '"+curdate+"' and  access ='1' and no_of_likes>='"+likes+"' and ";
    var counter=1;

        for(var k in where){
            if(counter==1)
            {
                que += k+"= '"+where[k]+"'";
            }
            else
            {
                que += " AND "+k+"= '"+where[k]+"' ";

            }
            counter++;
        }
        que +=" having distance <="+distance+ " order by distance" 
         console.log(que);    
 con.query(que, cb);
}

module.exports.getSearchData = function(lat, long, table, where, searchArr, user_pub_id, distance, cb) {
    var searchstring = searchArr.toString();
    googleTranslate.detectLanguage(searchstring, function(err, detection) {
        console.log('\nDetected Language: ' + detection.language);
        // =>  es
        if (detection.language == 'en') {
            googleTranslate.translate(searchstring, 'ar', function(err, translation) {
                var arabic = translation.translatedText;
                console.log('\narabic:' + arabic);

                //var finalStr= eng+' '+arabic+' '+arabictoeng+' '+searchstring;
                var finalStr = arabic + ',' + searchstring;
                var searchArr = [];
                searchArr = _.split(finalStr, ",");
                var edate = (new Date()).valueOf().toString();
                var curdate = edate.substr(0, 10);
                var pastdate = curdate - 86400;
                var pastdate = pastdate + '000';
                var curdate = curdate + '000';

                var que = "select *, ( 3959 * acos( cos( radians(" + lat + ") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians(" + long + ") ) + sin( radians(" + lat + ") ) * sin( radians( latitude ) ) ) ) AS distance from " + table + " where user_pub_id != '" + user_pub_id + "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='" + user_pub_id + "')   and  access ='1' and  updated_at between '" + pastdate + "' and '" + curdate + "' and ";
                var counter = 1;

                for (var k in where) {
                    if (counter == 1) {
                        que += k + "= '" + where[k] + "'";
                    } else {
                        que += " AND " + k + "= '" + where[k] + "' ";

                    }
                    counter++;
                }

                /*for (i = 0; i < searchArr.length; i++) {
                    if (i == 0) {
                        que += " and ( tagging like '%" + searchArr[i] + "%' ESCAPE '!'";
                    } else {
                        que += " or  tagging like '%" + searchArr[i] + "%' ESCAPE '!' ";
                    }
                    if (i == searchArr.length - 1) {
                        que += ")";
                    }
                }*/
                for (i = 0; i < searchArr.length; i++) {
                    if (i == 0) {
                        que += " and ( tagging like '%" + searchArr[i] + "%' ESCAPE '!' or additional_tagging like '%" + searchArr[i] + "%' ESCAPE '!' or description like '%" + searchArr[i] + "%' ESCAPE '!'";
                    } else { 
                        que += " or  tagging like '%" + searchArr[i] + "%' ESCAPE '!' or  additional_tagging like '%" + searchArr[i] + "%' ESCAPE '!' or description like '%" + searchArr[i] + "%' ESCAPE '!'";
                    }
                    if (i == searchArr.length - 1) {
                        que += ")";
                    }
                }

                que += " having distance <=" + distance + " order by distance"
                console.log(que);
                con.query(que, cb);

            });

        }
        //ELSE
        // =>  es
        else {
            googleTranslate.translate(searchstring, 'en', function(err, translation) {
                var eng = translation.translatedText;
                console.log('\neng:' + eng);

                //var finalStr= eng+' '+arabic+' '+arabictoeng+' '+searchstring;
                var finalStr = eng + ',' + searchstring;
                var searchArr = [];
                searchArr = _.split(finalStr, ",");
                var edate = (new Date()).valueOf().toString();
                var curdate = edate.substr(0, 10);
                var pastdate = curdate - 86400;
                var pastdate = pastdate + '000';
                var curdate = curdate + '000';

                var que = "select *, ( 3959 * acos( cos( radians(" + lat + ") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians(" + long + ") ) + sin( radians(" + lat + ") ) * sin( radians( latitude ) ) ) ) AS distance from " + table + " where user_pub_id != '" + user_pub_id + "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='" + user_pub_id + "')   and  access ='1' and  updated_at between '" + pastdate + "' and '" + curdate + "' and ";
                var counter = 1;

                for (var k in where) {
                    if (counter == 1) {
                        que += k + "= '" + where[k] + "'";
                    } else {
                        que += " AND " + k + "= '" + where[k] + "' ";

                    }
                    counter++;
                }

                for (i = 0; i < searchArr.length; i++) {
                    if (i == 0) {
                        que += " and ( tagging like '%" + searchArr[i] + "%' ESCAPE '!' or additional_tagging like '%" + searchArr[i] + "%' ESCAPE '!' or description like '%" + searchArr[i] + "%' ESCAPE '!'";
                    } else {
                        que += " or  tagging like '%" + searchArr[i] + "%' ESCAPE '!' or  additional_tagging like '%" + searchArr[i] + "%' ESCAPE '!' or description like '%" + searchArr[i] + "%' ESCAPE '!'";
                    }
                    if (i == searchArr.length - 1) {
                        que += ")";
                    }
                }

                que += " having distance <=" + distance + " order by distance"
                console.log(que);
                con.query(que, cb);
            });
        }
    });
}

module.exports.sendmail=function(user_email,subject,msg)
{
    var payload = {
        email_id: user_email,
        subject: subject,
        msg: msg
    };

 request({
      uri: "http://13.232.102.101/admin/index.php/Webservices/send_email/",
      method: "POST",
      form: payload
    }, function(error, response, body) {
      //console.log(response);
    })
}
