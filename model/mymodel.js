    
var con = require('../config/connect');
var base_url = "http://13.232.102.101/admin/";
var fs = require('fs');
var nodemailer = require('nodemailer');
const sendmail = require('sendmail')();
var _ = require('lodash');
var moment = require('moment');
var request = require('request');
 var googleTranslate = require('google-translate')('AIzaSyB0aTR_q7mn-eif8W-di1ZqIXYOHO5Wr78');// var fcm = require('fcm-notification');
   
var transporter = nodemailer.createTransport({
                host: 'ssl://smtp.googlemail.com',
                port: '465',
                secure: 'false', 
                auth: {
                    user: 'samyotechindore@gmail.com',
                    pass: 'Sam#123yo'
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
  var pastdate = curdate-8640000000000000;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';  
  var current_date = moment().valueOf();
    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   AND subscription_end_date>='"+current_date+"'  and  access ='1' AND  status=1 and ";
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
    console.log(que);
}

module.exports.getSearchDataWithoutTag=function(lat,long,table,where,user_pub_id,distance,cb)
{
  var edate = (new Date()).valueOf().toString();
  var curdate = edate.substr(0, 10);
  var pastdate = curdate-8640000000000000;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';
//    var currentdate = new Date();
//       currentdate = moment(currentdate,"DD-MM-YYYY");
   
//     var current_date=JSON.parse(JSON.stringify(currentdate))
var current_date = moment().valueOf();

    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  access ='1' AND is_sold='1' AND subscription_end_date>="+current_date+" AND  status=1 AND ";
    //var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  updated_at between '"+pastdate+"' and '"+curdate+"' and  access ='1' AND is_sold='1' AND  ";
    var counter=1;

        for(var k in where){
            //console.log("my k", k);
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
    //console.log('uperwaliiiiiiiiiiiii=======',que)
}
module.exports.getSearchKeywordDataWithoutTag=function(lat,long,table,where,searchArr,user_pub_id,distance,cb)
{
  var edate = (new Date()).valueOf().toString();
  var curdate = edate.substr(0, 10);
  var pastdate = curdate-8640000000000000;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';
//    var currentdate = new Date();
//       currentdate = moment(currentdate,"DD-MM-YYYY");
   
//     var current_date=JSON.parse(JSON.stringify(currentdate))
var current_date = moment().valueOf();

    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  access ='1' AND is_sold='1' AND subscription_end_date>="+current_date+" AND  status=1 AND ";
    //var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  updated_at between '"+pastdate+"' and '"+curdate+"' and  access ='1' AND is_sold='1' AND  ";
    var counter=1;

        for(var k in where){
            //console.log("my k", k);
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
        //var searchArr = ['car', "property"];
        for (i = 0; i < searchArr.length; i++) {
            searchArr[i] = (searchArr[i]).toLowerCase();
            if (i == 0) {
                que += " and ( LOWER(tagging) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(title) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(description) like '%" + searchArr[i] + "%' ESCAPE '!'";
            } else { 
                que += " or  LOWER(tagging) like '%" + searchArr[i] + "%' ESCAPE '!' or  LOWER(title) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(description) like '%" + searchArr[i] + "%' ESCAPE '!'";
            }
            if (i == searchArr.length - 1) {
                que += ")";
            }
        }

        que +=" having distance <="+distance+ " order by distance"  
    con.query(que, cb);
    //console.log('uperwaliiiiiiiiiiiii=======',que)
}

module.exports.getSearchDataWithoutTagSimilar=function(lat,long,table,where,user_pub_id, product_pub_id,distance,cb)
{
  var edate = (new Date()).valueOf().toString();
  var curdate = edate.substr(0, 10);
  var pastdate = curdate-8640000000000000;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';
//    var currentdate = new Date();
//       currentdate = moment(currentdate,"DD-MM-YYYY");
   
//     var current_date=JSON.parse(JSON.stringify(currentdate))
var current_date = moment().valueOf();

    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and pub_id!='"+product_pub_id+"' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  access ='1' AND is_sold='1' AND subscription_end_date>="+current_date+" AND  status=1 AND  ";
    //var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  updated_at between '"+pastdate+"' and '"+curdate+"' and  access ='1' AND is_sold='1' AND  ";
    var counter=1;

        for(var k in where){
            //console.log("my k", k);
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
    console.log('uperwaliiiiiiiiiiiii=======',que)
}

module.exports.getSearchDataForSimilar=function(lat,long,table,where,user_pub_id,distance,cb)
{
    var edate = (new Date()).valueOf().toString();
    var curdate = edate.substr(0, 10);
    var pastdate = curdate-8640000000000000;
    var pastdate= pastdate+'000';
    var curdate = curdate+'000';

    var current_date = moment().valueOf();

    var que ="select tab.*,cat.category_slug, sub_cat.category_slug as sub_category_slug, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( tab.latitude ) ) * cos( radians( tab.longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( tab.latitude ) ) ) ) AS distance from "+table+" as tab left join category as cat ON tab.category_pub_id=cat.pub_id left join category as sub_cat ON tab.sub_cat_pub_id=cat.pub_id  where tab.user_pub_id != '"+user_pub_id+ "' and tab.user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  tab.access ='1' AND tab.is_sold='1' AND tab.subscription_end_date>="+current_date+" AND  status=1 AND  ";
    //var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  updated_at between '"+pastdate+"' and '"+curdate+"' and  access ='1' AND is_sold='1' AND  ";
    var counter=1;

    for(var k in where){
        if(counter==1)
        {
            que += "tab."+k+"= '"+where[k]+"'";
        }
        else
        {
            que += " AND "+"tab." + k+"= '"+where[k]+"' ";

        }
        counter++;
    }
    que +=" having distance <="+distance+ " order by distance"  
    con.query(que, cb);
    //console.log('uperwaliiiiiiiiiiiii=======',que)
}

module.exports.getSearchDataWithoutTagBetween=function(lat,long,table,where,user_pub_id,distance,start_year,end_year,cb)
{
  var edate = (new Date()).valueOf().toString();
  var curdate = edate.substr(0, 10);
  var pastdate = curdate-8640000000000000;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';
  var currentdate = new Date();
      currentdate = moment(currentdate,"DD-MM-YYYY");
      var current_date = moment().valueOf();    
    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where  user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  access ='1' AND is_sold='1' AND subscription_end_date >="+current_date+" and car_year between '"+start_year+"' and '"+end_year+"' AND  status=1 and ";
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
        que +=" having distance <="+distance+ " order by distance";
        

 con.query(que, cb);
}

module.exports.getSearchBetweenPrice=function(lat,long,table,where,user_pub_id,distance,start_price,end_price,cb)
{
  var edate = (new Date()).valueOf().toString();
  var curdate = edate.substr(0, 10);
  var pastdate = curdate-8640000000000000;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';
  var current_date = moment().valueOf();
    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"') AND subscription_end_date>="+current_date+"   and  access ='1' and price between '"+start_price+"' and '"+end_price+"' AND  status=1 and ";
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
  var pastdate = curdate-8640000000000000;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';
  var current_date = moment().valueOf();

    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+"  where user_pub_id = '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list  where user_pub_id !='"+user_pub_id+"')   AND subscription_end_date>="+current_date+" and  access ='1' and no_of_likes>='"+likes+"' AND  status=1 and ";
    
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
module.exports.getLikee = function( user_pub_id,pro_pub_id, cb) {
       var que = "select * from likes where user_pub_id='"+user_pub_id+"' and product_pub_id='"+pro_pub_id+"'";
        con.query(que, cb);
}

module.exports.getSearchData = function(lat, long, table, where, searchArr, user_pub_id, distance, cb) {
    var searchstring = searchArr.toString();
    //console.log(searchstring);
    
    googleTranslate.detectLanguage(searchstring, function(err, detection) {
        var current_date = moment().valueOf();
        if(err && typeof detection == "undefined"){
            var edate = (new Date()).valueOf().toString(); 
                var curdate = edate.substr(0, 10);
                var pastdate = curdate - 86400;
                var pastdate = pastdate + '000';
                var curdate = curdate + '000';

                var que = "select t.*, ( 3959 * acos( cos( radians(" + lat + ") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians(" + long + ") ) + sin( radians(" + lat + ") ) * sin( radians( latitude ) ) ) ) AS distance from " + table + " as t join category as c on t.category_pub_id=c.pub_id join category_details as cd on c.category_id=cd.category_id where user_pub_id != '" + user_pub_id + "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='" + user_pub_id + "')   and  access ='1' AND t.subscription_end_date>="+current_date+" AND  t.status=1 and ";
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
                    searchArr[i] = (searchArr[i]).toLowerCase();
                    if (i == 0) {
                        que += " and ( LOWER(tagging) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(title) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(t.description) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(cd.category_name) like '%" + searchArr[i] + "%' ESCAPE '!'";
                    } else { 
                        que += " or  LOWER(tagging) like '%" + searchArr[i] + "%' ESCAPE '!' or  LOWER(title) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(t.description) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(cd.category_name) like '%" + searchArr[i] + "%' ESCAPE '!'";
                    }
                    if (i == searchArr.length - 1) {
                        que += ")";
                    }
                }

                que += " having distance <=" + distance + " order by distance"
                //console.log(que);
                con.query(que, cb);
        }
        else{

        console.log('\nDetected Language: ' + detection.language);
        // =>  es
        if (detection.language == 'en') {
            googleTranslate.translate(searchstring, 'ar', function(err, translation) {
                var arabic = translation.translatedText;
                console.log('\narabic:' + arabic);

                //var finalStr= eng+' '+arabic+' '+arabictoeng+' '+searchstring;
                var finalStr = arabic + ',' + searchstring;
                var searchArr = [];
                finalStr = finalStr.split(/[ ,]+/).join(',');
                searchArr = _.split(finalStr, ",");
                var edate = (new Date()).valueOf().toString(); 
                var curdate = edate.substr(0, 10);
                var pastdate = curdate - 86400;
                var pastdate = pastdate + '000';
                var curdate = curdate + '000';

                var que = "select t.*, ( 3959 * acos( cos( radians(" + lat + ") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians(" + long + ") ) + sin( radians(" + lat + ") ) * sin( radians( latitude ) ) ) ) AS distance from " + table + " as t join category as c on t.category_pub_id=c.pub_id join category_details as cd on c.category_id=cd.category_id  where user_pub_id != '" + user_pub_id + "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='" + user_pub_id + "')   and  t.access ='1'  AND t.subscription_end_date>="+current_date+" AND  t.status=1 and ";
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
                    searchArr[i] = (searchArr[i]).toLowerCase();
                    if (i == 0) {
                        que += " and ( LOWER(tagging) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(title) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(t.description) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(cd.category_name) like '%" + searchArr[i] + "%' ESCAPE '!'";
                    } else { 
                        que += " or  LOWER(tagging) like '%" + searchArr[i] + "%' ESCAPE '!' or  LOWER(title) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(t.description) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(cd.category_name) like '%" + searchArr[i] + "%' ESCAPE '!'";
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
                finalStr = finalStr.split(/[ ,]+/).join(',');
                searchArr = _.split(finalStr, ",");
                var edate = (new Date()).valueOf().toString();
                var curdate = edate.substr(0, 10);
                var pastdate = curdate - 86400;
                var pastdate = pastdate + '000';
                var curdate = curdate + '000';
                // removed condition of updated at between for getting last 24 hours product
                //updated_at between '" + pastdate + "' and '" + curdate + "' and
                var que = "select t.*, ( 3959 * acos( cos( radians(" + lat + ") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians(" + long + ") ) + sin( radians(" + lat + ") ) * sin( radians( latitude ) ) ) ) AS distance from " + table + " as t join category as c on t.category_pub_id=c.pub_id join category_details as cd on c.category_id=cd.category_id  where user_pub_id != '" + user_pub_id + "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='" + user_pub_id + "')   AND t.subscription_end_date>="+current_date+"  and  t.access ='1' AND  t.status=1 and  ";
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
                    searchArr[i] = (searchArr[i]).toLowerCase();
                    if (i == 0) {
                        que += " and ( LOWER(tagging) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(additional_tagging) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(t.description) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(cd.category_name) like '%" + searchArr[i] + "%' ESCAPE '!'";
                    } else {
                        que += " or  LOWER(tagging) like '%" + searchArr[i] + "%' ESCAPE '!' or  LOWER(additional_tagging) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(t.description) like '%" + searchArr[i] + "%' ESCAPE '!' or LOWER(cd.category_name) like '%" + searchArr[i] + "%' ESCAPE '!'";
                    }
                    if (i == searchArr.length - 1) {
                        que += ")";
                    }
                }

                que += " having distance <=" + distance + " order by distance"
                
                con.query(que, cb);
            });
        }
        }
    });
}

/*module.exports.sendmail=function(user_email,subject,msg)
{
    var payload = {
        email_id: user_email,
        subject: subject,
        msg: msg
    };

 request({
      uri: "http://13.232.102.101/admin/index.php/Webservices/send_email_new_v2/",
      method: "POST",
      form: payload
    }, function(error, response, body) {
      console.log(response);
    })
}*/
module.exports.sendmail=function(user_email,subject,msg,next)
{
    var api_key = '8f3175b39b9bf12d1ef673c91ade4a90-f8faf5ef-72773d7a';
    var domain = 'mg.ekeymarket.com';
    var mailgun = require('mailgun-js')({apiKey: api_key, domain: domain});

    var data = {
        from: 'Key Market <no-reply@ekeymarket.com>',
        to: user_email,
        subject: subject,
        text: msg,
        //html: html
        };
        
        mailgun.messages().send(data, function (error, body) {
            if(!error && next){
                next(body);
            }else{
                console.log(error);
            }
        });

    /*var payload = {
        email_id: user_email,
        subject: subject,
        msg: msg
    };

 request({
      uri: "http://13.232.102.101/admin/index.php/Webservices/send_email_new_v2/",
      method: "POST",
      form: payload
    }, function(error, response, body) {
      console.log(response);
    })*/
}

module.exports.getSearchAlldata=function(lat,long,table,where,distance,cb)
{
  var edate = (new Date()).valueOf().toString();
  var curdate = edate.substr(0, 10);
  var pastdate = curdate-8640000000000000;
  var pastdate= pastdate+'000';
  var curdate = curdate+'000';

    var que ="select *, ( 3959 * acos( cos( radians("+lat+") ) * cos( radians( latitude ) ) * cos( radians( longitude ) - radians("+long+") ) + sin( radians("+lat+") ) * sin( radians( latitude ) ) ) ) AS distance from "+table+" where user_pub_id != '"+user_pub_id+ "' and user_pub_id not in (select block_user_pub_id from block_list where user_pub_id ='"+user_pub_id+"')   and  updated_at between '"+pastdate+"' and '"+curdate+"' and  access ='1' AND  status=1 and ";
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

module.exports.online_st=function(user_pub_id, status, cb)
{
    var que ="update user set online_status="+status+" where pub_id='"+user_pub_id+ "'";
    con.query(que, function(err, data){
        //console.log(que);
    });
}

module.exports.getOnlineConnects=function(user_pub_id, cb)
{
    var que = "SELECT * FROM chat WHERE user_pub_id='"+user_pub_id+"'  or  user_pub_id_receiver ='"+user_pub_id+"'";
    var result_arr = [];
    con.query(que, function(err, connects){
        connects.forEach(row => {
            if(row.user_pub_id == user_pub_id){
                result_arr.push(row.user_pub_id_receiver);
            }
            else{
                result_arr.push(row.user_pub_id);
            }
        });
        result_arr = result_arr.filter(onlyUnique);
        cb(result_arr);
    });

    function onlyUnique(value, index, self) { 
        return self.indexOf(value) === index;
    }
}
module.exports.getUserData=function(user_pub_id, cb)
{
    var que = "SELECT * FROM user WHERE pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}