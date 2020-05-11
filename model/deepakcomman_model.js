var con = require('../newconfig/connect');
 var fcm = require('fcm-notification');
    var FCM = new fcm('./privatekey.json');
var utf8 = require('utf8');
    var base_url = "http://13.232.102.101/admin/";
    var cdn_base_url="https://d24omluomygbgb.cloudfront.net/thumbnails/";
module.exports.getSinglerow=function(table,where, cb)
{
        var que = "SELECT * FROM "+table+" WHERE "+where;
        con.query(que, cb);
       // //console.log(que);
}
module.exports.getChatHistory=function(user_pub_id, cb)
{
    var que = "SELECT * FROM chat WHERE user_pub_id='"+user_pub_id+"'  or  user_pub_id_receiver ='"+user_pub_id+"'  order by date desc ";
    //console.log(que);
    con.query(que, cb);
}

module.exports.getAdminChat=function(cb)
{
    var que = "SELECT * FROM chat WHERE user_pub_id='KEYMARKETSUPER' and user_pub_id_receiver ='KEYMARKETSUPER' order by date desc ";
    //console.log(que);
    con.query(que, cb);
}

module.exports.getAdminChatV1=function(cb)
{
    var que = "SELECT * FROM chat WHERE user_pub_id='KEYMARKETSUPER' and user_pub_id_receiver ='KEYMARKETSUPER' order by date asc ";
    //console.log(que);
    con.query(que, cb);
}

module.exports.getNotificationsV1=function(user_pub_id, cb)
{
    var que = "SELECT * FROM `notifications` WHERE `user_pub_id` = '"+user_pub_id+"' OR `type` = 'All' ORDER BY `created_at` DESC";    //console.log(que);
    con.query(que, cb);
}

module.exports.getUserName=function(user_name, cb)
{
    var que = "SELECT * FROM `user` WHERE `user_name` = '"+user_name+"'";    
    con.query(que, cb);
}

module.exports.getChatHistory2=function(user_pub_id, cb)
{
    var que = "SELECT * FROM chat WHERE user_pub_id_receiver='"+user_pub_id+"'  group by user_pub_id order by date desc ";
    con.query(que, cb);
}

module.exports.getUnreadCount=function(user_pub_id,user_pub_id_receiver,cb)
{
    var que="SELECT * FROM `chat` WHERE (`user_pub_id` = '"+user_pub_id_receiver+"' AND `user_pub_id_receiver` = '"+user_pub_id+"' and  chat_state='0') ";
    con.query(que, cb);
}
module.exports.getallData=function(table,cb)
{
    var que = "SELECT * FROM "+table;
    con.query(que, cb);
}

module.exports.getAllDataWithImage=function(table,cb)
{
    var que = "SELECT *,CONCAT('"+base_url+"',image) as image FROM "+table;
    con.query(que, cb);
}

module.exports.getCategoryWithLanguage=function(language,table,where,cb)
{
    if(language== 'ar' || language == 'AR')
    {
        var que = "SELECT category_id,pub_id,category_name_ar as category_name,description_ar AS description,CONCAT('"+base_url+"',image) as image FROM "+table +" WHERE "+where;
    }
    else
    {
        var que = "SELECT category_id,pub_id,category_name,description,CONCAT('"+base_url+"',image) as image FROM "+table +" WHERE "+where;
    }
    con.query(que, cb);
}

module.exports.getSubCategoryWithLanguage=function(language,table,where,cb)
{
    if(language== 'ar' || language == 'AR')
    {
        var que = "SELECT cat_pub_id,pub_id,name_ar as category_name FROM "+table +" WHERE "+where;
    }
    else
    {
        var que = "SELECT cat_pub_id,pub_id,name_en as category_name FROM "+table +" WHERE "+where;
    }
    con.query(que, cb);
}

module.exports.getBrandWithLanguage=function(language,table,cb)
{
    if(language== 'ar' || language == 'AR')
    {
        var que = "SELECT cat_pub_id,id,pub_id,brand_name_ar as brand_name FROM "+table;
    }
    else
    {
        var que = "SELECT cat_pub_id,id,pub_id,brand_name_en as brand_name FROM "+table;
    }

    con.query(que, cb);
}

module.exports.getBrandWhereLanguage=function(language,table,where,cb)
{
    if(language== 'ar' || language == 'AR')
    {
        var que = "SELECT cat_pub_id,id,pub_id,brand_name_ar as brand_name FROM "+table+" WHERE "+where;
    }
    else
    {
        var que = "SELECT cat_pub_id,id,pub_id,brand_name_en as brand_name FROM "+table+" WHERE "+where;
    }

    con.query(que, cb);
}

module.exports.getModelWithLanguage=function(language,table,where,cb)
{
    if(language== 'ar' || language == 'AR')
    {
        var que = "SELECT brand_pub_id,id,pub_id,model_name_ar as model_name FROM "+table+" WHERE "+where;
    }
    else
    {
        var que = "SELECT brand_pub_id,id,pub_id,model_name_en as model_name FROM "+table+" WHERE "+where;
    }

    con.query(que, cb);
}

module.exports.productInfo=function(product_pub_id,cb)
{
   var que = "SELECT u.* FROM product p join user u on p.user_pub_id=u.pub_id and p.pub_id='"+product_pub_id+"'";
    con.query(que, cb);
}
module.exports.getCount=function(table,where, cb)
{
    var que = "SELECT COUNT(*) AS `numrows` FROM "+table+" WHERE "+ where;
    con.query(que, cb);
}
module.exports.getChatData=function(sender_id,receiver_id,cb)
{
var que="SELECT * FROM `chat` WHERE (`user_pub_id` = '"+sender_id+"' AND `user_pub_id_receiver` = '"+receiver_id+"' ) or( `user_pub_id` = '"+receiver_id+"' and `user_pub_id_receiver` = '"+sender_id+"' )";
        
            con.query(que, cb);
}
module.exports.getChatData_blank=function(sender_id,receiver_id,cb)
{
var que="SELECT * FROM `chat` WHERE (`user_pub_id` = '"+sender_id+"' AND `user_pub_id_receiver` = '"+receiver_id+"' ) or( `user_pub_id` = '"+receiver_id+"' and `user_pub_id_receiver` = '"+sender_id+"' )";
        
            con.query(que, cb);
}

module.exports.deleteChat=function(sender_id,receiver_id,cb)
{
var que="DELETE FROM `chat` WHERE (`user_pub_id` = '"+sender_id+"' AND `user_pub_id_receiver` = '"+receiver_id+"' ) or( `user_pub_id` = '"+receiver_id+"' and `user_pub_id_receiver` = '"+sender_id+"' )";
        
            con.query(que, cb);
}

module.exports.follower=function(user_pub_id,cb)
{
    var que="SELECT *  FROM `followers` join user on followers.user_pub_id = user.pub_id WHERE following_user_pub_id = '"+user_pub_id+"' and user.status=1";
    con.query(que, cb);
}

module.exports.getLikeUsers=function(product_pub_id,cb)
{
    var que="SELECT user.name,user.pub_id as user_pub_id,CONCAT( '"+base_url+"',  user.profile_image) AS profile_img  FROM `likes` join user on likes.user_pub_id = user.pub_id WHERE product_pub_id = '"+product_pub_id+"' order by likeID DESC limit 3";
    con.query(que, cb);
}

module.exports.getCommentsUsers=function(product_pub_id,cb)
{
    var que="SELECT comments.content,comments.createAt,user.name,user.pub_id as user_pub_id,CONCAT( '"+base_url+"',  user.profile_image) AS profile_img  FROM `comments` join user on comments.user_pub_id = user.pub_id WHERE product_pub_id = '"+product_pub_id+"' and flag=1 order by commentID DESC limit 3";
    con.query(que, cb);
}

module.exports.following=function(user_pub_id,cb)
{
var que="SELECT  * FROM `followers` join user on followers.following_user_pub_id = user.pub_id WHERE user_pub_id = '"+user_pub_id+"' and user.status=1";
            con.query(que, cb);
}
module.exports.getMediaDatails=function(product_pub_id,cb)
{
// var que="SELECT  media_id,pub_id,media_url,CONCAT('"+cdn_base_url+"',thumb_url) as thumb_url,product_pub_id,created_at,updated_at,status FROM `user_media`  WHERE product_pub_id = '"+product_pub_id+"' ";
            var que="SELECT  * FROM `user_media`  WHERE product_pub_id = '"+product_pub_id+"' ";
            con.query(que, cb);
}
module.exports.getallDataWhere=function(table,obj,cb)
{

    con.connect(function(err){
    var que = "SELECT * FROM  "+table+" WHERE ";
        var counter=1;
        for(var k in obj){
            if(counter==1)
            {
                que += k+"= '"+obj[k]+"'";
            }
            else
            {
                que += " AND "+k+"= '"+obj[k]+"' ";

            }
            counter++;
        }
   
    // //console.log(que);
    con.query(que, cb);
    })
}
module.exports.getNotifications=function(user_pub_id,cb)
{
    var que= "select * from notifications where user_pub_id='"+user_pub_id+"' order by created_at desc";
      con.query(que, cb);
}
module.exports.getview=function(product_pub_id,cb)
{
    con.connect(function(err){
    

    var que = "SELECT DISTINCT u.pub_id as user_pub_id, u.name AS viewer_name,CONCAT( '"+base_url+"',  u.profile_image) AS viewer_profile_img,p.pub_id as product_pub_id,v.created_at FROM view v LEFT OUTER JOIN product p ON v.product_pub_id = p.pub_id LEFT OUTER JOIN user u ON v.user_pub_id = u.pub_id LEFT OUTER JOIN user_media um ON v.product_pub_id = um.product_pub_id WHERE v.product_pub_id = '"+product_pub_id+"' ";
    
    con.query(que, cb);
    })
}
module.exports.getBlockList=function(user_pub_id,cb)
{
    con.connect(function(err){
    

    var que = "SELECT DISTINCT u.pub_id as user_pub_id, u.name AS profile_name,u.user_name AS userName,CONCAT( '"+base_url+"',  u.profile_image) AS profile_img,b.created_at FROM block_list b  LEFT OUTER JOIN user u ON b.block_user_pub_id = u.pub_id  WHERE b.user_pub_id = '"+user_pub_id+"'";
   
    con.query(que, cb);
    })
}
module.exports.blockStatus=function(user_pub_id,block_user_pub_id,cb)
{
    con.connect(function(err){
    

    var que = "SELECT * FROM `block_list` WHERE (`user_pub_id` = '"+user_pub_id+"' AND `block_user_pub_id` = '"+block_user_pub_id+"' ) or( `user_pub_id` = '"+block_user_pub_id+"' and `block_user_pub_id` = '"+user_pub_id+"')";
   
    con.query(que, cb);
    })
}
module.exports.getlike=function(product_pub_id,cb)
{
    con.connect(function(err){
    

    var que = "SELECT DISTINCT u.pub_id as user_pub_id, u.name AS viewer_name,CONCAT( '"+base_url+"',  u.profile_image) AS viewer_profile_img,p.pub_id as product_pub_id,l.created_at FROM likes l   JOIN product p ON l.product_pub_id = p.pub_id  JOIN user u ON u.pub_id=l.user_pub_id   JOIN user_media um ON l.product_pub_id = um.product_pub_id WHERE l.product_pub_id = '"+product_pub_id+"' ";
    
    con.query(que, cb);
    })
}
module.exports.getcomment=function(product_pub_id,cb)
{
    con.connect(function(err){
    var que = "SELECT DISTINCT l.commentID ,l.content,l.flag, u.pub_id as user_pub_id, u.name AS user_name,CONCAT( '"+base_url+"',  u.profile_image) AS user_image,p.pub_id as product_pub_id,l.createAt  FROM comments l   JOIN product p ON l.product_pub_id = p.pub_id  JOIN user u ON u.pub_id=l.user_pub_id   JOIN user_media um ON l.product_pub_id = um.product_pub_id WHERE l.product_pub_id = '"+product_pub_id+"'  order by createAt";
    con.query(que, cb);
    })
}

module.exports.getMyRating=function(user_pub_id,cb)
{
    con.connect(function(err){
    var que = "SELECT DISTINCT l.id ,l.comment,l.rating, u.pub_id as user_pub_id, u.name AS user_name,CONCAT( '"+base_url+"',  u.profile_image) AS user_image,l.created_at  FROM rating l  JOIN user u ON u.pub_id=l.user_pub_id   WHERE l.user_pub_id_to_rate = '"+user_pub_id+"'  order by id";
    con.query(que, cb);
    })
}

module.exports.getcommentReply=function(product_pub_id,comment_id,cb)
{
    con.connect(function(err){
    var que = "SELECT DISTINCT l.commentID as comment_id,l.comment_id as commentID ,l.content,l.flag, u.pub_id as user_pub_id, u.name AS user_name,CONCAT( '"+base_url+"',  u.profile_image) AS user_image,p.pub_id as product_pub_id,l.createAt  FROM comment_reply l   JOIN product p ON l.product_pub_id = p.pub_id  JOIN user u ON u.pub_id=l.user_pub_id   JOIN user_media um ON l.product_pub_id = um.product_pub_id WHERE l.product_pub_id = '"+product_pub_id+"'  and l.comment_id = '"+comment_id+"' order by createAt";
    con.query(que, cb);
    })
}

module.exports.getforward=function(product_pub_id,cb)
{
    con.connect(function(err){
    

    var que = "SELECT DISTINCT u.pub_id AS forword_to_user_pub_id, u.name AS forword_to_viewer_name, CONCAT('"+base_url+"', u.profile_image) AS forword_to_viewer_profile_img, r.pub_id AS forword_by_user_pub_id, r.name AS forword_by_user_name, CONCAT('"+base_url+"', r.profile_image) AS forword_by_viewer_profile_img, p.pub_id AS product_pub_id, l.created_at FROM forward l LEFT OUTER JOIN product p ON l.product_pub_id = p.pub_id LEFT OUTER JOIN user u ON l.forword_to_pub_id = u.pub_id LEFT OUTER JOIN user r ON l.forword_by_pub_id = r.pub_id LEFT OUTER JOIN user_media um ON l.product_pub_id = um.product_pub_id WHERE l.product_pub_id = '"+product_pub_id+"' ";
   
    con.query(que, cb);
    })
}

module.exports.getpurchaseRequestInfoReciver=function(user_pub_id,cb)
{
    con.connect(function(err){
    

    var que = "select pp.id,pp.sender_pub_id,pp.receiver_pub_id ,u.name as sender_name ,CONCAT('"+base_url+"', u.profile_image) as sender_profile_img,pp.status,p.pub_id,DATE_FORMAT(p.created_at, '%d %b %Y %h:%i %p') as created_at ,c.category_name,p.tagging,CONCAT('"+base_url+"', um.thumb_url)  as product_thumb_img,CONCAT('"+base_url+"', um.media_url) as product_video_url  from product_purchase pp left outer join product p on pp.product_pub_id=p.pub_id left outer join category c on p.category_pub_id=c.pub_id left outer join user u on pp.sender_pub_id=u.pub_id left outer join user_media um on pp.product_pub_id=um.product_pub_id where pp.receiver_pub_id='"+user_pub_id+"'";
    //console.log(que);  
    con.query(que, cb);
    })
}
module.exports.getpurchaseRequestInfoSender=function(user_pub_id,cb)
{
    con.connect(function(err){
    var que = "select pp.id,pp.sender_pub_id,pp.receiver_pub_id ,u.name as receiver_name ,CONCAT('"+base_url+"', u.profile_image) as receiver_profile_img,pp.status,p.pub_id, DATE_FORMAT(p.created_at, '%d %b %Y %h:%i %p') as created_at ,c.category_name,p.tagging,CONCAT('"+base_url+"', um.thumb_url) as product_thumb_img, CONCAT('"+base_url+"', um.media_url) as product_video_url  from product_purchase pp left outer join product p on pp.product_pub_id=p.pub_id left outer join user u on pp.receiver_pub_id=u.pub_id left outer join category c on p.category_pub_id=c.pub_id left outer join user_media um on pp.product_pub_id=um.product_pub_id where pp.sender_pub_id='"+user_pub_id+"'";
    //console.log(que);  
    con.query(que, cb);
    })
}

module.exports.insert=function(table, obj, cb)
{
    con.connect(function(err){
        var que = "INSERT INTO "+table+" (";
        var counter = 1;
        for(var k in obj){
            if (counter==1) {
                que += " `"+k+"`"
            }
            else{
                que += ", `"+k+"`"
            }
            counter++;
        }   
        que += ") VALUES ( ";
        var counter = 1;
            for (var l in obj) {
                if (counter==1) {
                    que += "'"+obj[l]+"'"
                }else{
                    que += ", "+"'"+obj[l]+"'"
                }       
                counter++;
            }
        que += ")";
        //console.log(que);
        con.query(que, cb);
    });
}
module.exports.update=function(table, where, obj, cb)
{
    var que = "UPDATE "+table+" SET ";
    var counter=1;
    for(var k in obj){
    if(counter==1){
         que += k+" = '"+obj[k]+"'"
    }
    else{
    que += ", "+k+" = '"+obj[k]+"'"
    }
     counter++;
    }
    var key = Object.keys(where);
    que += " WHERE "+key[0]+" = '"+where[key[0]]+"'";
    con.query(que, cb);
}

module.exports.getCurrentVersion=function(device_type, cb)
{
    var que = "select * from app_version  where device_type='"+device_type+"' order by id desc ";
  
    con.query(que, cb);
}

module.exports.updateproduct=function(table, pub_id,user_pub_id, obj, cb)
{
    var que = 'UPDATE product set status =0 where pub_id="'+pub_id+'" and user_pub_id="'+user_pub_id+'"';

  console.log(que)
  con.query(que, cb);
  
}

module.exports.deactiveProduct=function(pub_id,user_pub_id,cb)
{
    var que = 'UPDATE product set status = 0 where pub_id="'+pub_id+'" and user_pub_id="'+user_pub_id+'"';
  con.query(que, cb);
  
}

module.exports.updateProductAccess=function(table, pub_id,user_pub_id,access, cb)
{
    var que = "UPDATE product set access ="+access+" where pub_id='"+pub_id+"' and user_pub_id='"+user_pub_id+"'";
   
    con.query(que, cb);
}

module.exports.updateProductSold=function(table, pub_id,user_pub_id,is_sold, cb)
{
    var sold_date=(new Date()).valueOf().toString();
    var que = "UPDATE product set is_sold ="+is_sold+", sold_date ='"+sold_date+"' where pub_id='"+pub_id+"' and user_pub_id='"+user_pub_id+"'";

    con.query(que, cb);
}

module.exports.dislike=function(product_pub_id,user_pub_id,cb)
{
    var que = "delete from likes where product_pub_id='"+product_pub_id+"' and user_pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}
module.exports.unFollow=function(user_pub_id,following_user_pub_id,cb)
{
    var que = "delete from followers where following_user_pub_id='"+following_user_pub_id+"' and user_pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}
module.exports.unblock=function(block_user_pub_id,user_pub_id,cb)
{
    var que = "delete from block_list where block_user_pub_id='"+block_user_pub_id+"' and user_pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}


module.exports.deleteBlockListByUserPubId=function(user_pub_id,cb)
{
    var que = "delete from block_list where user_pub_id='"+user_pub_id+"'";
    con.query(que);
    var que = "delete from block_list where block_user_pub_id='"+user_pub_id+"'";
    con.query(que,cb);
}
module.exports.deleteChatbyUserPubId=function(user_pub_id,cb)
{
    var que = "delete from chat where user_pub_id='"+user_pub_id+"'";
    con.query(que);
    var que = "delete from chat where user_pub_id_receiver='"+user_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteComplaintbyUserPubId=function(user_pub_id,cb)
{
    var que = "delete from complaint where user_pub_id='"+user_pub_id+"'";
    con.query(que);
    var que = "delete from complaint where friend_pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteCommentbyUserPubId=function(user_pub_id,cb)
{
    var que = "delete from comments where user_pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteFollowersByUserPubId=function(user_pub_id,cb)
{
     var que = "delete from followers where user_pub_id='"+user_pub_id+"'";
     con.query(que);
     var que = "delete from followers where following_user_pub_id='"+user_pub_id+"'";
     con.query(que, cb);
}
module.exports.deleteForwardByUserPubId=function(user_pub_id,cb)
{
     var que = "delete from forward where forword_by_pub_id='"+user_pub_id+"'";
     con.query(que);
     var que = "delete from forward where forword_to_pub_id='"+user_pub_id+"'";
     con.query(que, cb);
}

module.exports.deleteFeedbackByUserPubId=function(user_pub_id,cb)
{
    var que = "delete from feedback where user_pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteLikebyUserPubId=function(user_pub_id,cb)
{
    var que = "delete from likes where user_pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteNotificationbyUserPubId=function(user_pub_id,cb)
{
    var que = "delete from notifications where user_pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteProductReportbyUserPubId=function(user_pub_id,cb)
{
    var que = "delete from product_report where user_pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteProductPurchasebyUserPubId=function(user_pub_id,cb)
{
    var que = "delete from product_purchase where sender_pub_id='"+user_pub_id+"'";
    con.query(que);
    var que = "delete from product_purchase where receiver_pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteUserbyUserPubId=function(user_pub_id,cb)
{
    var que = "delete from user where pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteViewbyUserPubId=function(user_pub_id,cb)
{
    var que = "delete from view where user_pub_id='"+user_pub_id+"'";
    con.query(que, cb);
}

module.exports.deleteCommentsbyProductPubId=function(product_pub_id,cb)
{
    var que = "delete from comments where product_pub_id='"+product_pub_id+"'";
    con.query(que, cb);
}

module.exports.deleteForwardbyProductPubId=function(product_pub_id,cb)
{
    var que = "delete from forward where product_pub_id='"+product_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteLikesbyProductPubId=function(product_pub_id,cb)
{
    var que = "delete from likes where product_pub_id='"+product_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteProductsbyProductPubId=function(product_pub_id,cb)
{
    var que = "delete from product where pub_id='"+product_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteProductPurchasebyProductPubId=function(product_pub_id,cb)
{
    var que = "delete from product_purchase where product_pub_id='"+product_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteProductReportbyProductPubId=function(product_pub_id,cb)
{
    var que = "delete from product_report where product_pub_id='"+product_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteUserMediabyProductPubId=function(product_pub_id,cb)
{
    var que = "delete from user_media where product_pub_id='"+product_pub_id+"'";
    con.query(que, cb);
}
module.exports.deleteViewbyProductPubId=function(product_pub_id,cb)
{
    var que = "delete from view where product_pub_id='"+product_pub_id+"'";
    con.query(que, cb);
}

module.exports.deleteComment=function(commentID,cb)
{
    var que = "delete from comments where commentID='"+commentID+"'";
    con.query(que, cb);
}
module.exports.getadmin=function(table, where,cb)
{
    var que = "SELECT * FROM "+table+"WHERE "+where;
    con.query(que, cb) 
}
//MONTY
module.exports.bulkinsert=function(table, cols,values)
{
   //console.log('model');
}
module.exports.pushnotificationChatImage=function(user_name,msg,receiver_token,type='70001')
{
    FCM.send({                                                  
        notification:{
            title : 'Chat',
            body :  user_name + ': Image'
        },
        token : receiver_token
        }, function(err, response) {
        if(err){
            // //console.log('error found', err);
        }else {
            //console.log('response here', response);
        }
    });
}

module.exports.pushnotification=function(user_name,msg,receiver_token,type='70001')
{
     var message={
      android :{
          ttl:10000,
          priority:'high',
          data: {
                 title : user_name,
                 type : type,
                 body : decodeURIComponent(msg) 
                 }
      },
      apns: {

             payload: {
                        ttl:10000,
                        priority:'high',
                        data: {
                             title : user_name,
                             type : type,
                             body : decodeURIComponent(msg) 
                            },
                        aps: {
                            badge: 0,
                            sound : "bingbong.aiff",
                            alert : decodeURIComponent(msg),
                            "content-available" : 1
                            }
                     },
    },
      token : receiver_token
  };
  FCM.send(message,function(err,response){
      if(err){
      //console.log('error found',err);

  }
  else
  {
      //console.log('response here',response);
  }
});

}

module.exports.pushnotificationSocket=function(user_name,msg,receiver_token,senderId,senderName,senderImage,receiverId,wantToCall,callType,type='70001')
{
     var message={
      android :{
          ttl:10000,
          priority:'high',
          data: {
                 title : "video call",
                 type : type,
                 senderId : senderId,
                 senderName : senderName,
                 senderImage : senderImage,
                 receiverId : receiverId,
                 wantToCall : wantToCall,
                 callType : callType,
                 body : decodeURIComponent(msg) 
                 }
      },
      apns: {

             payload: {
                        ttl:10000,
                        priority:'high',
                        data: {
                            title : "video call",
                             type : type,
                             senderId : senderId,
                             senderName : senderName,
                             senderImage : senderImage,
                             receiverId : receiverId,
                             wantToCall : wantToCall,
                             callType : callType,
                             body : decodeURIComponent(msg) 
                            },
                        aps: {
                            badge: 0,
                            sound : "bingbong.aiff",
                            alert : decodeURIComponent(msg),
                            "content-available" : 1
                            }
                     },
    },
      token : receiver_token
  };
  FCM.send(message,function(err,response){
      if(err){
      console.log('error found',err);

  }
  else
  {
      
  }
});

}

module.exports.pushnotificationV2=function(user_name, msg,receiver_token,data,type='70003')
{
  var message={
      android :{
          ttl:10000,
          priority:'high',
          data:data
          
      },
      apns: {

             payload: {
                        ttl:10000,
                        priority:'high',
                        data: data,
                        aps: {
                            badge: 0,
                            sound : "bingbong.aiff",
                            alert : decodeURIComponent(msg),
                            "content-available" : 1
                            }
                     },
    },
      token : receiver_token
  };
  console.log(data);
  FCM.send(message,function(err,response){
      if(err){
      console.log('error found',err);

  }
  else
  {
      console.log('response here',response);
  }
});
}

module.exports.pushnotificationChat=function(user_name,msg,receiver_token,sender_id,type='70001')
{
     var message={
      android :{
          ttl:10000,
          priority:'high',
          data: {
                 title : user_name,
                 type : type,
                 sender_id : sender_id,
                 sender_name : user_name,
                 body : decodeURIComponent(msg) 
                 }
      },
      apns: {

             payload: {
                        ttl:10000,
                        priority:'high',
                        data: {
                             title : user_name,
                             type : type,
                             sender_id : sender_id,
                             body : decodeURIComponent(msg) 
                            },
                        aps: {
                            badge: 0,
                            sound : "bingbong.aiff",
                            alert : decodeURIComponent(msg),
                            "content-available" : 1
                            }
                     },
    },
      token : receiver_token
  };
  FCM.send(message,function(err,response){
      if(err){
      //console.log('error found',err);

  }
  else
  {
      //console.log('response here',response);
  }
});

}
// type  70002 for android comment
module.exports.pushnotificationComment=function(user_name,msg,receiver_token,type='70005',product_pub_id='')
{

var message={
      android :{
          ttl:10000,
          priority:'high',
          data: {
                 title : 'keyMarket',
                 type : type,
                 product_pub_id:product_pub_id,
                 body : decodeURIComponent(msg) 
                 }
          
      },
      apns: {

             payload: {
                        ttl:10000,
                        priority:'high',
                        data: {
                             title : 'keyMarket',
                             type : type,
                             product_pub_id:product_pub_id,
                             body : decodeURIComponent(msg) 
                            },
                        aps: {
                            badge: 0,
                            sound : "bingbong.aiff",
                            alert : decodeURIComponent(msg),
                            "content-available" : 1 
                            }
                     },
    },
      token : receiver_token
  };
  FCM.send(message,function(err,response){
      if(err){
      //console.log('error found',err);

  }
  else
  {
      //console.log('response here',response);
  }
});

}

module.exports.pushnotificationTest=function()
{
    FCM.send({                                               
        data:{
            title : 'Chat',
            body : 'hello'
        },
        notification:{
            title : 'Chat',
            body : 'asasa'
        },
        token : "cUe7QDABnwE:APA91bFb-C2_F0aQe9vbmU0j413_AUXtynllrRkVj0_eoaHP97X86oDjFp1FGLZ2k9dt_nRH0XZF1m-VP_auJW2rLlZ55772LI0_df-xblHz0QciLW5EoRVEouDIUz7AP9GNXOu4VFrD"
        }, function(err, response) {
        if(err){
            //console.log('error found', err);
        }else {
            //console.log('response here', response);
        }
    });
}

module.exports.sendmail=function(user_name,msg,receiver_token)
{
//console.log('mail code here');

}
module.exports.search=function(table, obj,user_pub_id,cb)
{
 
    var que = "SELECT * FROM "+table+" WHERE pub_id !='"+user_pub_id+"' and   (country_code,mobile_number) IN (";
    
    var counter=1;
    for(var k in obj){
        // //console.log(obj);
        if(!isNaN(obj[k].code) && !isNaN(obj[k].mobile)) {
        if(counter==1){
            que += "("+obj[k].code+","+obj[k].mobile+")"
        }
        else{
            que += ", ("+obj[k].code+","+obj[k].mobile+")"
        }
      }
     counter++;
    }
    // var key = Object.keys(where);
    que += ")";
    
    con.query(que, cb);
}

module.exports.randomString=function(length, chars) {
    var result = '';
    for (var i = length; i > 0; --i) result += chars[Math.floor(Math.random() * chars.length)];
    return result;
}