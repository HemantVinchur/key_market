var constant = require('./constant/constant');
var constantAR = require('./constant/constantAR');
var constantEN = require('./constant/constant');
var mailgun = require('./model/mailgun');
var express = require('express');
//var cloudinary = require('cloudinary');
var cloudinary = require('cloudinary').v2;
//var connect = require('connect');
var QRCode = require('qrcode');
var qr = require('qr-image')
var app = express();
//var app = connect();
var bodyParser = require('body-parser');
var multer = require('multer');
var sha1 = require('sha1');
var uniqid = require('uniqid');
var crypto = require('crypto');
var FfmpegCommand = require('fluent-ffmpeg');
var command = new FfmpegCommand();
var thumbler = require('video-thumb');
var fs = require('fs');
var path = require('path');
var nrc = require('node-run-cmd');
var snap1 = {}
var db = require('./db');
var validator = require("email-validator");
var msg91 = require('msg91-sms');
var _ = require('lodash');
var base_url = "http://13.232.102.101/admin/";
var request = require('request');
var googleTranslate = require('google-translate')('AIzaSyB0aTR_q7mn-eif8W-di1ZqIXYOHO5Wr78');
var https = require('https');
var privateKey = fs.readFileSync('/home/ec2-user/ssl/keys/ekeymarket.key', 'utf8');
var certificate = fs.readFileSync('/home/ec2-user/ssl/certs/26357deb426a0e02.crt', 'utf8');
var cacer = fs.readFileSync('/home/ec2-user/ssl/certs/gd_bundle-g2-g1.crt', 'utf8');
const httpsPort = 8099;
var msg91 = require("msg91")("205521Ay0uGpRMiR5da996d7", "KEYIND", "4");
var sinch_key = '7716d2f4-0b37-4f0a-bb1b-2719d9b03130';
var sinch_secret = 'frs2g8kvQEmha1G2eSvWnA==';
var moment = require('moment');
var socket = require("socket.io");

//for packages imges
var pakg_adver_url = "https://ekeymarket.com:" + httpsPort + "/public/";
var bannerImage_path = 'http://13.232.102.101' + ':4000' + '/public/images/advertisment/';
var credentials = {
    key: privateKey,
    cert: certificate,
    ca: cacer
};
//  var httpsServer = https.createServer(credentials, app).listen(httpsPort, () => {
//    console.log(">> CentraliZr listening at port " + httpsPort);
// });
var owner_name = "";
var httpServer = https.createServer(credentials, app);
httpServer.listen(httpsPort);
var io = socket.listen(httpServer);

global.app_socket = require("./socket")(io);

app.use(bodyParser.json({
    limit: '10mb',
    extended: true
}))
app.use(bodyParser.urlencoded({
    limit: '10mb',
    extended: true
}));

app.use('/public', express.static("admin/public"));

//console.log("KEY: ", options.key)
//console.log("CERT: ", options.cert)

// var fcm = require('fcm-notification');
// var FCM = new fcm('./privatekey.json');
// var token = 'dswCLV-gQzI:APA91bFlPKu0e6j7wPpBztTwg--i-n_tszjrphUfpL99TY58p5mc18HlhYBg9XmnSdhmW4esWAHnNLlKfmoQfo_FX25J2ghxxY4kVJYSKHjtRU62PEhxN6f9zJ-re4un5FbQOaCary04';
//MONTY
var aws = require('aws-sdk'); // ^2.2.41
var multerS3 = require('multer-s3'); //"^1.4.1"



aws.config.update({
    secretAccessKey: 'AlgyETYalQzPy/vsAkngKmQwkGzVnmepiH7MRJWK',
    accessKeyId: 'AKIAJW6BSU5K5W33QSFA',
    region: 'ap-southeast-1'
});
//var s3 = new aws.S3();
var s3 = new aws.S3({
    useAccelerateEndpoint: true
});

var nodemailer = require('nodemailer');
var transporter = nodemailer.createTransport({
    service: 'gmail',
    auth: {
        user: 'samyotechindore@gmail.com',
        pass: 'Sam%123yo'
    }
});
const mailOptions = {
    from: 'samyotechindore@gmail.com', // sender address
    to: 'tahabarwah5253@gmail.com', // list of receivers
    subject: 'Subject of your email', // Subject line
    html: fs.writeFile('./index.html') // plain text body
};
//     const fileName = './index.html'
// const myString = 'abc';
// const scope = {};
// const callback = () => {};


// const mailOptions = {
//     from: 'samyotechindore@gmail.com', // sender address
//     to: 'tahabarwah5253@gmail.com', // list of receivers
//     subject: 'Subject of your email', // Subject line
//     html: fs.writeFile(fileName, myString, (err) => {
//   if (err) throw err;

//   console.log('=> done  ' + fileName);
//   callback.apply(scope, [fileName]);
// })

// };

var cm = require("./model/comman_model");
var my = require("./model/mymodel");
//app.use(express.json({limit: '50mb'}));
//app.use(connect.urlencoded({limit: '50mb'}));
var lang_id = 1;

app.use(function(req, res, next) { //allow cross origin requests
    res.setHeader("Access-Control-Allow-Methods", "POST, PUT, OPTIONS, DELETE, GET");
    res.header("Access-Control-Allow-Origin", "http://localhost");
    res.header("Access-Control-Allow-Headers", "Origin, X-Requested-With, Content-Type, Accept");
    if (req.url == '/signUp' || req.url == '/deleteCloudnary' || req.url == '/signIn' || req.url == '/forgotPassword' || req.url == '/getCurrentVersion' || req.url == '/send_otp' || req.url == '/verifyUser')

    {
        next();
    } else {
        if (req.headers.language == 'ar' || req.headers.language == 'AR') {
            lang_id = 2;
            req.body.language = 2;
            constant = constantAR;
        } else {
            lang_id = 1;
            req.body.language = 1;
            constant = constantEN;
        }

        //console.log(req.headers);
        /*if (!req.headers.device_token || !req.headers.user_pub_id) {
            res.json({
                status: 3,
                message: constant.SESSION_CLOSED
            });
            return;
        } else {
            cm.getallDataWhere('user', {
                pub_id: req.headers.user_pub_id,
                device_token: req.headers.device_token
            }, function(err, auth) {
                if (auth.length > 0) {
                    if (auth[0].status == 0) {
                        res.json({
                            status: 4,
                            message: constant.DEACTIVE_ACCOUNT
                        });
                        return;
                    }
                } else {

                    res.json({
                        status: 3,
                        message: constant.SESSION_CLOSED
                    });
                    return;
                }

            });
        }*/
        next();

    }
});

/** Serving from the same express Server
No cors required */
app.use(express.static('../client'));
app.use(bodyParser.json());

var storage = multer.diskStorage({ //multers disk storage settings
    destination: function(req, file, cb) {
        cb(null, '../../../../../var/www/html/admin/assets/product_upload');
    },
    filename: function(req, file, cb) {
        var datetimestamp = Date.now();
        cb(null, "snap" + '-' + datetimestamp + '.' + file.originalname.split('.')[file.originalname.split('.').length - 1]);
    }
});


var upload = multer({
    storage: multerS3({
        s3: s3,
        bucket: 'ekeymark',
        acl: 'public-read',
        key: function(req, file, cb) {

            var datetimestamp = Date.now();
            if (req.body.sound == 'false') {
                cb(null, "muted/snap" + '-' + datetimestamp + '.' + file.originalname.split('.')[file.originalname.split('.').length - 1]); //muted case 
            } else {
                cb(null, "snap" + '-' + datetimestamp + '.' + file.originalname.split('.')[file.originalname.split('.').length - 1]); //use Date.now() for unique file keys
            }
        }
    })
});

var image = multer.diskStorage({ //multers disk storage settings
    destination: function(req, file, cb) {
        cb(null, '../../../../../var/www/html/admin/assets/images/profile/');
    },
    filename: function(req, file, cb) {
        var datetimestamp = Date.now();
        cb(null, file.fieldname + '-' + datetimestamp + '.' + file.originalname.split('.')[file.originalname.split('.').length - 1]);
    }
});

app.delete('/mycallback', function(req, res) {
    cloudinary.config({
        cloud_name: 'keymarket',
        api_key: '316747885545466',
        api_secret: 'YZt07kRp2v71aMdhZvNBYZjF4vs'
    });

    cloudinary.api.delete_resources(['2367481559570490531'], {
            keep_original: true
        },
        function(error, result) {});
});

app.get('/deleteCloudnary', function(req, res) {
    var code = req.query.code;
    var url = 'https://316747885545466:YZt07kRp2v71aMdhZvNBYZjF4vs@api.cloudinary.com/v1_1/keymarket/resources/video/upload?public_ids[]=keymarket/2367481559570490531'
    var options = {
        method: 'delete',
        url: url
    }
    request(options, function(err, res) {})
})

app.post("/updateIosFireBaseToken", function(req, res) {
    if (!req.body.pub_id || !req.body.firebase_token_ios) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.update('user', {
            pub_id: req.body.pub_id
        }, {
            firebase_token_ios: req.body.firebase_token_ios,
            updated_at: (new Date()).valueOf().toString()
        }, function(err, result) {

            res.send({
                "status": 1,
                "message": "Firebase_token Updated",
            });

        })
    }
});
var upload_image = multer({ //multer settings
    storage: image
}).array('image');

var Chat = multer.diskStorage({ //multers disk storage settings
    destination: function(req, file, cb) {
        cb(null, '../../../../../var/www/html/admin/assets/chat_media/');
    },
    filename: function(req, file, cb) {
        var datetimestamp = Date.now();
        cb(null, file.fieldname + '-' + datetimestamp + '.' + file.originalname.split('.')[file.originalname.split('.').length - 1]);
    }
});


var upload_chat = multer({ //multer settings
    storage: Chat
}).array('image');

app.post("/sinchOtp", async function(req, res) {
    var mobile_number = req.body.mobile_number;
    var country_code = req.body.country_code;
    var auth = "Basic " + new Buffer(sinch_key + ":" + sinch_secret).toString("base64");
    var timestamp = new Date().toISOString();
    await request({
        uri: "https://verificationapi-v1.sinch.com/verification/v1/verifications",
        method: "POST",
        headers: {
            "content-type": "application/json",
            "charset": "UTF-8",
            "x-timestamp": timestamp,
            "Authorization": auth
        },
        body: JSON.stringify({
            "identity": {
                "type": "number",
                "endpoint": "+" + country_code + mobile_number,
            },
            "custom": "verif_code_" + timestamp,
            "reference": "verif_keymarket_" + timestamp,
            "method": "sms",
            "metadata": {
                "os": "rest",
                "platform": "N/A"
            }
        })
    }, function(error, response, body) {
        if (error != null) {
            res.send({
                "status": 0,
                "message": constant.SINCH_OTP_SEND_ERR
            });
        } else {
            res.send({
                "status": 1,
                "message": constant.SINCH_OTP_SEND
            });
        }
    });
});

/*
app.post("/verifyOtp",async function(req, res) {
    var mobile_number = req.body.mobile_number;
    var country_code = req.body.country_code;
    var timestamp = new Date().toISOString();
    var otp = req.body.otp;
    var auth = "Basic " + new Buffer(sinch_key + ":" + sinch_secret).toString("base64");
    await request({
        uri: "https://verificationapi-v1.sinch.com/verification/v1/verifications/number/+"+country_code+mobile_number,
        method: "PUT",
        headers : {
            "content-type": "application/json",
            "charset":"UTF-8",
            "x-timestamp": timestamp,
            "Authorization" : auth
        },
        body:JSON.stringify({
            "source": "manual",
            "sms": {
              "code": otp
            },
            "method": "sms"
          })
    }, function(error, response, body) {
        var resBody = JSON.parse(body);
     
        if(resBody.status == 'SUCCESSFUL' || resBody.status == 'successful'){
            var current_date = (new Date()).valueOf().toString();
            var random = Math.random().toString(16);
            var str = crypto.createHash('sha1').update(random + current_date).digest('hex');
            var pub_id = str;
            var user_name= country_code+mobile_number+'KMUser';
                cm.getallDataWhere('user', {
                    mobile_number: mobile_number,
                    country_code: country_code
                }, function(err, userResult) {
                    if (userResult.length == 0) {
        
                        var code = qr.image(pub_id, {
                            type: 'png',
                            ec_level: 'H',
                            size: 10,
                            margin: 0
                        });
                        var ss = path.join('../../../../../var/www/html/admin/assets/barcode_image/', pub_id + '.png');
                        var output = fs.createWriteStream(ss);
                        code.pipe(output);
                        var qr_image = "/assets/barcode_image/" + pub_id + ".png"
                        var userdata = {
                            pub_id: pub_id,
                            user_name: user_name,
                            name: user_name,
                            mobile_number: mobile_number,
                            QR_image: qr_image,
                            signup_type: 0,
                            country_code: country_code,
                            device_token: req.body.device_token,
                            device_type: req.body.device_type,
                            created_at: (new Date()).valueOf().toString(),
                            updated_at: (new Date()).valueOf().toString(),
                            signup_at: (new Date()).valueOf().toString()
                        };
        
                        cm.insert('user', userdata, function(err, result) {
                            cm.getallDataWhere('user', {
                                pub_id: pub_id
                            }, function(err, userData) {
                                if (userData.length > 0) {
                                    userData[0].QR_image = base_url + userData[0].QR_image;
                                    userData[0].profile_image = base_url + userData[0].profile_image;
                                }
        
                                res.send({
                                    "status": 1,
                                    "message": constant.USER_REGISTER,
                                    "data": userData[0]
                                });
                            });
                        });
                    } else {
                        cm.getallDataWhere('user', {
                            mobile_number: mobile_number,
                            country_code: country_code,
                        }, function(err, userData) {
                            
                            if (userData.length > 0) {
                                if(userData[0].status == 0){
                                    res.send({
                                        "status": 0,
                                        "message": "Your account has been blocked, please contact admin",
                                        "data": {}
                                    });
                                }else{

                                
                                userData[0].profile_image = base_url + userData[0].profile_image;
                                if (userData[0].QR_image == "") {
                                    var code = qr.image(userData[0].pub_id, {
                                        type: 'png',
                                        ec_level: 'H',
                                        size: 10,
                                        margin: 0
                                    });
                                    var ss = path.join('../../../../../var/www/html/admin/assets/barcode_image/', pub_id + '.png');
                                    var output = fs.createWriteStream(ss);
                                    code.pipe(output);
                                    var qr_image = "/assets/barcode_image/" + userData[0].pub_id + ".png"
        
                                    cm.update('user', {
                                        mobile_number: mobile_number,
                                        country_code: country_code,
                                    }, {
                                        QR_image: qr_image,
                                    }, function(err, updateresult) {});
                                    userData[0].QR_image = base_url + qr_image;
                                }
        
                                if (userData[0].user_name == "") {
                                    cm.update('user', {
                                        mobile_number: mobile_number,
                                        country_code: country_code,
                                    }, {
                                        user_name: user_name,
                                    }, function(err, updateresult) {});
        
                                    userData[0].user_name = user_name;
                                }
        
                                cm.update('user', {
                                    mobile_number: mobile_number,
                                    country_code: country_code,
                                }, {
                                        device_token: req.body.device_token,
                                        device_type: req.body.device_type,
                                    }, function(err, updateresult) {});
            
                                    userData[0].QR_image = base_url + userData[0].QR_image;
                                }
            
                                res.send({
                                    "status": 1,
                                    "message": constant.USER_REGISTER,
                                    "data": userData[0]
                                });
                            }
                        });
                    }
                });
        } else { 
            res.send({
                "status": 0,
                "message": constant.SINCH_OTP_VERIFY_ERR
            });
        }
    });
});*/

app.post("/verifyOtp", async function(req, res) {
    var mobile_number = req.body.mobile_number;
    var country_code = req.body.country_code;
    var timestamp = new Date().toISOString();
    var otp = req.body.otp;
    var auth = "Basic " + new Buffer(sinch_key + ":" + sinch_secret).toString("base64");
    await request({
        uri: "https://verificationapi-v1.sinch.com/verification/v1/verifications/number/+" + country_code + mobile_number,
        method: "PUT",
        headers: {
            "content-type": "application/json",
            "charset": "UTF-8",
            "x-timestamp": timestamp,
            "Authorization": auth
        },
        body: JSON.stringify({
            "source": "manual",
            "sms": {
                "code": otp
            },
            "method": "sms"
        })
    }, function(error, response, body) {
        var resBody = JSON.parse(body);

        if (resBody.status == 'SUCCESSFUL' || resBody.status == 'successful') {
            var current_date = (new Date()).valueOf().toString();
            var random = Math.random().toString(16);
            var str = crypto.createHash('sha1').update(random + current_date).digest('hex');
            var pub_id = str;
            //var user_name= country_code+mobile_number+'KMUser';
            var user_name = uniqid.process();
            cm.getallDataWhere('user', {
                mobile_number: mobile_number,
                country_code: country_code
            }, function(err, userResult) {
                if (userResult.length == 0) {

                    var code = qr.image(pub_id, {
                        type: 'png',
                        ec_level: 'H',
                        size: 10,
                        margin: 0
                    });
                    var ss = path.join('../../../../../var/www/html/admin/assets/barcode_image/', pub_id + '.png');
                    var output = fs.createWriteStream(ss);
                    code.pipe(output);
                    var qr_image = "/assets/barcode_image/" + pub_id + ".png"
                    var userdata = {
                        pub_id: pub_id,
                        user_name: user_name,
                        name: user_name,
                        mobile_number: mobile_number,
                        QR_image: qr_image,
                        signup_type: 0,
                        country_code: country_code,
                        device_token: req.body.device_token,
                        device_type: req.body.device_type,
                        created_at: (new Date()).valueOf().toString(),
                        updated_at: (new Date()).valueOf().toString(),
                        signup_at: (new Date()).valueOf().toString()
                    };

                    cm.insert('user', userdata, function(err, result) {
                        //console.log("err insert user on OTP verify", err);
                        cm.getallDataWhere('user', {
                            pub_id: pub_id
                        }, function(err, userData) {
                            if (userData.length > 0) {
                                userData[0].QR_image = base_url + userData[0].QR_image;
                                userData[0].profile_image = base_url + userData[0].profile_image;
                            }

                            res.send({
                                "status": 1,
                                "message": constant.USER_REGISTER,
                                "data": userData[0]
                            });
                        });
                    });
                } else {
                    var userData = userResult;
                    if (userData[0].status == 0) {
                        res.send({
                            "status": 0,
                            "message": "Your account has been blocked, please contact admin",
                            "data": {}
                        });
                    } else {


                        userData[0].profile_image = base_url + userData[0].profile_image;
                        if (userData[0].QR_image == "") {
                            var code = qr.image(userData[0].pub_id, {
                                type: 'png',
                                ec_level: 'H',
                                size: 10,
                                margin: 0
                            });
                            var ss = path.join('../../../../../var/www/html/admin/assets/barcode_image/', pub_id + '.png');
                            var output = fs.createWriteStream(ss);
                            code.pipe(output);
                            var qr_image = "/assets/barcode_image/" + userData[0].pub_id + ".png"

                            cm.update('user', {
                                mobile_number: mobile_number,
                                country_code: country_code,
                            }, {
                                QR_image: qr_image,
                            }, function(err, updateresult) {});
                            userData[0].QR_image = base_url + qr_image;
                        }

                        if (userData[0].user_name == "" || userData[0].user_name == "undefined") {
                            cm.update('user', {
                                mobile_number: mobile_number,
                                country_code: country_code,
                            }, {
                                user_name: user_name,
                            }, function(err, updateresult) {});

                            userData[0].user_name = user_name;
                        }

                        cm.update('user', {
                            mobile_number: mobile_number,
                            country_code: country_code,
                        }, {
                            device_token: req.body.device_token,
                            device_type: req.body.device_type,
                        }, function(err, updateresult) {});

                        userData[0].QR_image = base_url + userData[0].QR_image;
                    }

                    res.send({
                        "status": 1,
                        "message": constant.USER_REGISTER,
                        "data": userData[0]
                    });
                }
            });
        } else {
            res.send({
                "status": 0,
                "message": constant.SINCH_OTP_VERIFY_ERR
            });
        }
    });
});

app.post("/getCountsByProduct", function(req, res) {
    if (!req.body.product_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD,
            "data": { likes: 0, views: 0, comments: 0 }
        });
        return;
    } else {
        cm.getLikeViewCount(req.body.product_pub_id, function(err, result) {
            var data = { likes: 0, views: 0, comments: 0 };
            if (result.length > 0) {
                data.likes = result[0].likeCount;
                data.views = result[0].viewCount;
            } else {
                data.likes = 0;
                data.views = 0;
            }
            cm.getCommentCount(req.body.product_pub_id, function(err1, result1) {
                if (result1.length > 0) {
                    data.comments = result1[0].commentCount;
                } else {
                    data.comments = 0;
                }
                cm.getForwardCount(req.body.product_pub_id, function(err1, result2) {
                    if (result2.length > 0) {
                        data.forwards = result2[0].forwardCount;
                    } else {
                        data.forwards = 0;
                    }
                    res.send({
                        "status": 1,
                        "message": "",
                        "total_counts": data
                    });
                });

            });
        });
    }
});

app.post("/signUp", function(req, res) {
    var current_date = (new Date()).valueOf().toString();
    var random = Math.random().toString(16);
    var str = crypto.createHash('sha1').update(random + current_date).digest('hex');
    var pub_id = str;
    if (req.body.email_id) {
        if (req.body.signup_type == 0) {
            var msg = constant.VERIFICATION_MAIL + req.body.otp + "." + constant.EMAIL_SIGNATURE;
            my.sendmail(req.body.email_id, constant.REG_SUB, msg);
        }
        var msg = constant.WELCOME_EMAIL + constant.EMAIL_SIGNATURE;
        my.sendmail(req.body.email_id, constant.REG_SUB, msg, function() {

        });

        var email_id = req.body.email_id;
        var current_date = (new Date()).valueOf().toString();
        var username = email_id.split('@');
        var user_name = username[0] + current_date;
        cm.getallDataWhere('user', {
            email_id: req.body.email_id
        }, function(err, result) {
            if (err) {

            } else {
                if (result.length == 0) {
                    var code = qr.image(pub_id, {
                        type: 'png',
                        ec_level: 'H',
                        size: 10,
                        margin: 0
                    });
                    var ss = path.join('../../../../../var/www/html/admin/assets/barcode_image/', pub_id + '.png');
                    var output = fs.createWriteStream(ss);
                    code.pipe(output);
                    var qr_image = "/assets/barcode_image/" + pub_id + ".png"

                    var userdata = {
                        pub_id: pub_id,
                        email_id: req.body.email_id,
                        user_name: user_name,
                        name: user_name,
                        signup_type: req.body.signup_type,
                        QR_image: qr_image,
                        device_token: req.body.device_token,
                        device_type: req.body.device_type,
                        created_at: (new Date()).valueOf().toString(),
                        updated_at: (new Date()).valueOf().toString(),
                        signup_at: (new Date()).valueOf().toString()
                    };
                    delete req.body.language;
                    cm.insert('user', userdata, function(err, result) {
                        cm.getallDataWhere('user', {
                            pub_id: pub_id
                        }, function(err, userData) {
                            if (userData.length > 0) {
                                userData[0].profile_image = base_url + userData[0].profile_image;
                                userData[0].QR_image = base_url + userData[0].QR_image;
                            }

                            res.send({
                                "status": 1,
                                "message": constant.USER_REGISTER,
                                "data": userData[0]
                            });
                        });
                    });
                } else {
                    cm.getallDataWhere('user', {
                        email_id: req.body.email_id
                    }, function(err, userData) {
                        if (userData.length > 0) {
                            userData[0].QR_image = base_url + userData[0].QR_image;
                            userData[0].profile_image = base_url + userData[0].profile_image;

                            if (userData[0].QR_image == "") {
                                var code = qr.image(userData[0].pub_id, {
                                    type: 'png',
                                    ec_level: 'H',
                                    size: 10,
                                    margin: 0
                                });
                                var ss = path.join('../../../../../var/www/html/admin/assets/barcode_image/', pub_id + '.png');
                                var output = fs.createWriteStream(ss);
                                code.pipe(output);
                                var qr_image = "/assets/barcode_image/" + userData[0].pub_id + ".png"

                                userData[0].QR_image = base_url + qr_image;
                                cm.update('user', {
                                    email_id: req.body.email_id
                                }, {
                                    QR_image: qr_image,
                                }, function(err, updateresult) {});
                            }

                            if (userData[0].user_name == "") {
                                userData[0].user_name = user_name;
                                cm.update('user', {
                                    email_id: req.body.email_id
                                }, {
                                    user_name: user_name,
                                }, function(err, updateresult) {});
                            }

                            cm.update('user', {
                                email_id: req.body.email_id
                            }, {
                                device_token: req.body.device_token,
                                device_type: req.body.device_type,
                            }, function(err, updateresult) {});
                        }

                        res.send({
                            "status": 1,
                            "message": constant.USER_REGISTER,
                            "data": userData[0]
                        });
                    });
                }
            }
        });
    }

    if (req.body.mobile_number) {
        if (req.body.country_code == "91") {
            var senderId = "KEYIND";
        } else {
            var senderId = "KEYMARKTOTP";
        }

        var msg = "Use " + req.body.otp + constant.VERIFICATION_MSG;
        var number = req.body.country_code + req.body.mobile_number;
        var user_name = req.body.country_code + req.body.mobile_number + 'KMUser';

        if (req.body.country_code == "91") {
            msg91.send(number, msg, function(err, response) {
                //console.log(response);
            });
        } else {
            request({
                uri: "http://www.oursms.net/api/sendsms.php?username=keymarket&password=Khts@1397&message=" + msg + "&numbers=" + number + "&sender=" + senderId + "&unicode=e&Rmduplicated=1&return=json",
                method: "GET",
                form: 'test'
            }, function(error, response, body) {});
        }

        /*        request({
                    uri: "http://www.oursms.net/api/sendsms.php?username=keymarket&password=K12345678&message=" + msg + "&numbers=" + number + "&sender=" + senderId + "&unicode=e&Rmduplicated=1&return=json",
                    method: "GET",
                    form: 'test'
                }, function(error, response, body) {});*/

        cm.getallDataWhere('user', {
            mobile_number: req.body.mobile_number,
            country_code: req.body.country_code
        }, function(err, userResult) {
            if (userResult.length == 0) {

                var code = qr.image(pub_id, {
                    type: 'png',
                    ec_level: 'H',
                    size: 10,
                    margin: 0
                });
                var ss = path.join('../../../../../var/www/html/admin/assets/barcode_image/', pub_id + '.png');
                var output = fs.createWriteStream(ss);
                code.pipe(output);
                var qr_image = "/assets/barcode_image/" + pub_id + ".png"
                var userdata = {
                    pub_id: pub_id,
                    user_name: user_name,
                    name: user_name,
                    mobile_number: req.body.mobile_number,
                    QR_image: qr_image,
                    signup_type: req.body.signup_type,
                    country_code: req.body.country_code,
                    device_token: req.body.device_token,
                    device_type: req.body.device_type,
                    created_at: (new Date()).valueOf().toString(),
                    updated_at: (new Date()).valueOf().toString(),
                    signup_at: (new Date()).valueOf().toString()
                };

                cm.insert('user', userdata, function(err, result) {
                    cm.getallDataWhere('user', {
                        pub_id: pub_id
                    }, function(err, userData) {
                        if (userData.length > 0) {
                            userData[0].QR_image = base_url + userData[0].QR_image;
                            userData[0].profile_image = base_url + userData[0].profile_image;
                        }

                        res.send({
                            "status": 1,
                            "message": constant.USER_REGISTER,
                            "data": userData[0]
                        });
                    });
                });
            } else {
                cm.getallDataWhere('user', {
                    mobile_number: req.body.mobile_number,
                    country_code: req.body.country_code,
                }, function(err, userData) {

                    if (userData.length > 0) {
                        userData[0].profile_image = base_url + userData[0].profile_image;
                        if (userData[0].QR_image == "") {
                            var code = qr.image(userData[0].pub_id, {
                                type: 'png',
                                ec_level: 'H',
                                size: 10,
                                margin: 0
                            });
                            var ss = path.join('../../../../../var/www/html/admin/assets/barcode_image/', pub_id + '.png');
                            var output = fs.createWriteStream(ss);
                            code.pipe(output);
                            var qr_image = "/assets/barcode_image/" + userData[0].pub_id + ".png"

                            cm.update('user', {
                                mobile_number: req.body.mobile_number,
                                country_code: req.body.country_code,
                            }, {
                                QR_image: qr_image,
                            }, function(err, updateresult) {});
                            userData[0].QR_image = base_url + qr_image;
                        }

                        if (userData[0].user_name == "") {
                            cm.update('user', {
                                mobile_number: req.body.mobile_number,
                                country_code: req.body.country_code,
                            }, {
                                user_name: user_name,
                            }, function(err, updateresult) {});

                            userData[0].user_name = user_name;
                        }

                        cm.update('user', {
                            mobile_number: req.body.mobile_number,
                            country_code: req.body.country_code,
                        }, {
                            device_token: req.body.device_token,
                            device_type: req.body.device_type,
                        }, function(err, updateresult) {});

                        userData[0].QR_image = base_url + userData[0].QR_image;
                    }

                    res.send({
                        "status": 1,
                        "message": constant.USER_REGISTER,
                        "data": userData[0]
                    });
                });
            }
        });
    }
});


app.get("/guestSignIn", function(req, res) {

    cm.getallDataWhere('user', {
        pub_id: req.body.email_id
    }, function(err, result) {
        if (err) {
            console.log(err);
        } else {
            var pub_id = 'KEYMARKETSUPER';
            cm.getallDataWhere('user', {
                pub_id: pub_id
            }, function(err, userData) {
                if (userData.length > 0) {
                    userData[0].profile_image = base_url + userData[0].profile_image;

                    if (userData[0].QR_image == "") {
                        var pub_id = userData[0].pub_id;
                        var code = qr.image(userData[0].pub_id, {
                            type: 'png',
                            ec_level: 'H',
                            size: 10,
                            margin: 0
                        });
                        var ss = path.join('../../../../../var/www/html/admin/assets/barcode_image/', pub_id + '.png');
                        var output = fs.createWriteStream(ss);
                        code.pipe(output);
                        var qr_image = "/assets/barcode_image/" + pub_id + ".png"

                        userData[0].QR_image = base_url + qr_image;
                        cm.update('user', {
                            pub_id: pub_id
                        }, {
                            QR_image: qr_image,
                        }, function(err, updateresult) {});
                    }
                }

                res.send({
                    "status": 1,
                    "message": constant.USER_REGISTER,
                    "data": userData[0]
                });
            });
        }
    });
});

app.post("/verifyUser", function(req, res) {
    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('user', {
            pub_id: req.body.user_pub_id
        }, function(err, result) {
            if (result.length > 0) {
                cm.update('user', {
                    pub_id: req.body.user_pub_id
                }, {
                    verify: 1
                }, function(err, updateresult) {
                    result[0].profile_image = base_url + result[0].profile_image;
                    res.send({
                        "status": 1,
                        "message": constant.USR_VERIFY,
                        "data": result[0]
                    });
                });
            } else {
                res.send({
                    "status": 0,
                    "message": constant.USER_NOT_FOUND
                });
            }
        });
    }
});

/*app.post("/setPassword", function(req, res) {
    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        if (!req.body.new_password || req.body.new_password.length < 8 || req.body.new_password.length > 20) {
            res.json({
                status: 0,
                message: constant.PASSWORD_LENGTH
            });
        } else {
            var new_password = sha1(req.body.new_password);

            cm.getallDataWhere('user', {
                pub_id: req.body.user_pub_id
            }, function(err, result) {
                if (err) {
                    console.log(err);
                } else {
                    if (result.length > 0) {
                        var msg = constant.MSGCHANGEPASSWORD;
                        cm.update('user', {
                            pub_id: req.body.user_pub_id,
                        }, {
                            password: new_password,
                            verify: 1,
                            updated_at: (new Date()).valueOf().toString()
                        }, function(err, result) {
                            if (err) {
                                console.log(err);
                            } else {
                                res.send({
                                    "status": 1,
                                    "message": constant.PWD_CNG
                                });
                            }
                        });

                    } else {
                        res.json({
                            status: 0,
                            message: constant.NOTAVAILABLE
                        });
                    }
                }
            });
        }
    }
});

app.post("/signIn", function(req, res) {

    if (!validator.validate(req.body.email_id) || !req.body.email_id) {
        res.json({
            status: 0,
            message: constant.CHECK_YOUR_EMAIL
        });
    } else {
        if (!req.body.password) { // || req.body.password.length < 8 || req.body.password.length > 20
            res.json({
                status: 0,
                message: constant.PASSWORD_LENGTH
            });
        } else {
            if (!req.body.device_token || !req.body.device_type) {
                res.json({
                    status: 0,
                    message: constant.CHKAllFIELD
                });
            } else {
                cm.getallDataWhere('user', {
                    email_id: req.body.email_id
                }, function(err, result) {
                    if (err) {
                        res.send({
                            "status": 0,
                            "message": constant.ERR
                        });
                    } else {

                        if (result.length == 0) {
                            res.json({
                                status: 0,
                                message: constant.USER_NOT_FOUND
                            });
                        } else {
                            if (result[0].password != sha1(req.body.password)) {

                                res.json({
                                    status: 0,
                                    message: constant.PASS_NT_MTCH
                                });
                            } else {
                                if (result[0].verify == '0') {
                                    result[0].profile_image = base_url + result[0].profile_image;
                                    res.send({
                                        "status": 1,
                                        "message": constant.VERIFYMOBILE,
                                        "data": result[0]
                                    });


                                } else if (result[0].status == '0') {
                                    res.send({
                                        "status": 0,
                                        "message": constant.DEACTIVATEUSER
                                    });
                                } else {
                                    cm.update('user', {
                                        email_id: req.body.email_id
                                    }, {
                                        device_type: req.body.device_type,
                                        device_token: req.body.device_token
                                    }, function(err, result_update) {
                                        if (err) {
                                            console.log(err);
                                        } else {
                                            if (result.length > 0) {
                                                result[0].profile_image = base_url + result[0].profile_image;
                                                res.send({
                                                    "status": 1,
                                                    "message": constant.LOGINSUCCESSFULL,
                                                    "data": result[0]
                                                });
                                            } else {

                                                res.send({
                                                    "status": 0,
                                                    "message": constant.USER_NOT_FOUND
                                                });
                                            }
                                        }

                                    })
                                }
                            }
                        }
                    }
                });
            }
        }
    }
});


app.post("/forgotPassword", function(req, res) {
    if (!req.body.email_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('user', {
                email_id: req.body.email_id
            },

            function(err, result) {

                if (err) {
                    res.send({
                        "status": 0,
                        "message": err
                    });
                } else {
                    if (result.length > 0) {
                        var password = cm.randomString(8, '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ');
                        var rand_paasword = sha1(password);
                        var msg = constant.MSGUPDATEDPASSWORD + ' ' + password;
                        my.sendmail(req.body.email_id, constant.PWD_SUB, msg);
                        cm.update('user', {
                            email_id: req.body.email_id
                        }, {
                            password: rand_paasword,
                            updated_at: (new Date()).valueOf().toString()
                        }, function(err, result) {
                            if (err) {
                                console.log(err);
                            } else {
                                res.send({
                                    "status": 1,
                                    "message": constant.PWD_CNG,
                                });
                            }
                        });
                    } else {
                        res.send({
                            "status": 0,
                            "message": EMAILIDNOTFOUND
                        });
                    }
                }
            });
    }
});

app.post("/changePassword", function(req, res) {
    if (!req.body.old_password || !req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        if (!req.body.new_password) {
            res.json({
                status: 0,
                message: constant.PASSWORD_LENGTH
            });
        } else {
            var old_password = sha1(req.body.old_password);
            var new_password = sha1(req.body.new_password);

            cm.getallDataWhere('user', {
                pub_id: req.body.user_pub_id
            }, function(err, result) {
                if (err) {
                    console.log(err);
                } else {
                    if (result.length > 0) {
                        if (result[0].password != sha1(req.body.old_password)) {
                            res.json({
                                status: 0,
                                message: constant.PASS_NT_MTCH
                            });
                        } else {
                            var msg = constant.MSGCHANGEPASSWORD;
                            cm.update('user', {
                                pub_id: req.body.user_pub_id
                            }, {
                                password: new_password,
                                updated_at: (new Date()).valueOf().toString()
                            }, function(err, result) {
                                if (err) {
                                    console.log(err);
                                } else {
                                    res.send({
                                        "status": 1,
                                        "message": constant.PWD_CNG
                                    });
                                }
                            });
                        }
                    } else {
                        res.json({
                            status: 0,
                            message: constant.NOTAVAILABLE
                        });
                    }
                }
            });
        }
    }
});*/


app.post("/getCurrentVersion", function(req, res) {
    if (!req.body.device_type) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getCurrentVersion(req.body.device_type, function(err, result) {
            if (result.length > 0) {
                res.send({
                    "status": 1,
                    "message": constant.CURRENT_VERSION,
                    "appVersion": result[0]
                });
            } else {
                res.send({
                    "status": 0,
                    "message": constant.NO_DATA
                });
            }
        });
    }
});

app.get("/getAllCategory", function(req, res) {
    cm.getAllDataWithImage('category', function(err, result) {

        if (err) {
            res.send({
                "status": 0,
                "message": constant.ERR
            });
        } else {
            if (result.length > 0) {
                res.send({
                    "status": 1,
                    "message": constant.ALL_CAT,
                    "data": result
                });
            } else {
                res.send({
                    "status": 0,
                    "message": constant.NO_DATA
                });
            }
        }
    });
});


app.post("/getGlobalData", function(req, res) {
    if (!req.body.language) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        var result_data = [];
        new Promise(function(resolve, reject) {


            cm.getCategoryWithLanguage(req.body.language, 'category', null, function(err, cat_result) {

                if (cat_result.length > 0) {

                    cat_result.forEach(async function(row, index) {
                        cm.getSubCategoryWithLanguage(req.body.language, row.category_id, function(sub_err, sub_cat_result) {

                            cat_result[index].sub_category = sub_cat_result;
                            if (row.category_slug == "car") {
                                cm.getBrandWithLanguage(req.body.language, 'car_brands', function(brand_err, brand_result) {

                                    if (brand_result.length > 0) {



                                        brand_result
                                            .reduce(function(promiesRes, branddata, index) {
                                                return promiesRes
                                                    .then(function(data) {

                                                        return new Promise(function(resolve, reject) {
                                                            var pub_id = branddata.pub_id;
                                                            cm.getModelWithLanguage(req.body.language, 'car_models', "model.brand_pub_id='" + pub_id + "'", function(model_err, result1) {
                                                                if (result1.length > 0) {
                                                                    branddata.car_model = result1;
                                                                } else {
                                                                    branddata.car_model = Array();
                                                                }
                                                                resolve(branddata);
                                                            });
                                                        });
                                                    })
                                                    .catch(function(error) {
                                                        res.send({
                                                            "status": 0,
                                                            "message": constant.INTERNAL_ERROR
                                                        });
                                                        return error.message;
                                                    })
                                            }, Promise.resolve(null)).then(arrayOfResults => {
                                                cat_result[index].brand_result = brand_result;
                                                resolve(
                                                    res.send({
                                                        "status": 1,
                                                        "message": constant.ALL_CAT,
                                                        "data": cat_result,
                                                        "global_config": {
                                                            "currency": "SAR"
                                                        }
                                                    }));
                                            });
                                    }
                                });
                            }
                        });
                    });
                }
            });
        });

    }
});



app.post("/getAllCarBrands", function(req, res) {
    cm.getallData('car_brands', function(err, brand_result) {

        if (err) {
            res.send({
                "status": 0,
                "message": constant.ERR
            });
        } else {
            brand_result
                .reduce(function(promiesRes, branddata, index) {
                    return promiesRes
                        .then(function(data) {

                            return new Promise(function(resolve, reject) {
                                var pub_id = branddata.pub_id;
                                cm.getallDataWhere('car_models', {
                                    brand_pub_id: pub_id
                                }, function(err, result1) {
                                    if (result1.length > 0) {
                                        branddata.car_model = result1;
                                    } else {
                                        branddata.car_model = Array();
                                    }
                                    resolve(branddata);
                                });
                            });
                        })
                        .catch(function(error) {
                            res.send({
                                "status": 0,
                                "message": constant.INTERNAL_ERROR
                            });
                            return error.message;
                        })
                }, Promise.resolve(null)).then(arrayOfResults => {

                    res.send({
                        "status": 1,
                        "message": constant.ALL_CAT,
                        "data": brand_result
                    });
                });
        }
    });
});


app.post("/getAllSubCategory", function(req, res) {
    if (!req.body.cat_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
    } else {
        cm.getallDataWhere('sub_category', {
            cat_pub_id: req.body.cat_pub_id
        }, function(err, result) {

            if (result.length > 0) {
                res.send({
                    "status": 1,
                    "message": constant.ALL_CAT,
                    "data": result
                });
            } else {
                res.send({
                    "status": 0,
                    "message": constant.NO_DATA
                });
            }
        });
    }
});

app.post("/getAllSubCategory", function(req, res) {
    if (req.body.category_pub_id) {
        cm.getallDataWhere('sub_category', {
                category_pub_id: req.body.category_pub_id
            },

            function(err, result) {

                if (err) {
                    res.send({
                        "status": 0,
                        "message": constant.ERR
                    });
                } else {
                    if (result.length > 0) {
                        res.send({
                            "status": 1,
                            "message": constant.ALL_CAT,
                            "data": result
                        });
                    } else {
                        res.send({
                            "status": 0,
                            "message": constant.NO_DATA
                        });
                    }
                }
            });
    } else {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    }
});

function errorLog(res, status, err) {
    res.send({
        "status": status,
        "message": err

    });
}

app.post("/changeEmail", function(req, res) {

    if (!req.body.pub_id || !req.body.email_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        var user_id = req.body.pub_id;
        cm.getallDataWhere('user', {
            email_id: req.body.email_id,
        }, function(err, result) {
            if (err) {
                console.log(err);
                errorLog(res, 0, err);
            } else {
                if (result.length == 0) {

                    cm.update('user', {
                        pub_id: user_id
                    }, req.body, function(err, result) {
                        if (err) {
                            errorLog(res, 0, err);

                        } else {
                            cm.getallDataWhere('user', {
                                pub_id: user_id
                            }, function(err, result) {
                                if (err) {
                                    errorLog(res, 0, err);

                                } else {
                                    result[0].profile_image = base_url + result[0].profile_image;
                                    result[0].QR_image = base_url + result[0].QR_image;
                                    res.send({
                                        "status": 1,
                                        "message": constant.PROFILE_UPDATED,
                                        "data": result[0]
                                    });
                                }
                            });
                        }
                    })

                } else {
                    errorLog(res, 0, constant.EMAIL_VALIDATION);

                    // res.send({
                    //     "status": 0,
                    //     "message": constant.EMAIL_VALIDATION
                    // });
                    return;
                }
            }
        });
    }
});

app.post("/sendOtp", function(req, res) {

    if (req.body.email_id) {
        cm.getallDataWhere('user', {
            email_id: req.body.email_id,
        }, function(err, result) {
            if (err) {
                console.log(err);
            } else {
                if (result.length == 0) {
                    var msg = constant.SEND_OTP_TEXT + req.body.otp + ". " + constant.EMAIL_SIGNATURE;
                    my.sendmail(req.body.email_id, constant.SEND_OTP, msg);
                    res.send({
                        "status": 1,
                        "message": constant.OTP_SEND_SUCCESS,
                    });
                } else {
                    res.send({
                        "status": 0,
                        "message": constant.EMAIL_VALIDATION
                    });
                    return;
                }
            }
        });
    }
    if (req.body.mobile_number) {
        cm.getallDataWhere('user', {
            mobile_number: req.body.mobile_number,
            country_code: req.body.country_code,
        }, function(err, result) {
            if (err) {
                console.log(err);
            } else {
                if (result.length == 0) {
                    if (req.body.country_code == "91") {
                        var senderId = "KEYIND";
                    } else {
                        var senderId = "KEYMARKTOTP";
                    }

                    var msg = "Use " + req.body.otp + constant.VERIFICATION_MSG;
                    var number = req.body.country_code + req.body.mobile_number;
                    if (req.body.country_code == "91") {
                        msg91.send(number, msg, function(err, response) {
                            //console.log(response);
                        });
                    } else {
                        request({
                            uri: "http://www.oursms.net/api/sendsms.php?username=keymarket&password=K12345678&message=" + msg + "&numbers=" + number + "&sender=" + senderId + "&unicode=e&Rmduplicated=1&return=json",
                            method: "GET",
                            form: 'test'
                        }, function(error, response, body) {});
                    }

                    res.send({
                        "status": 1,
                        "message": constant.OTP_SEND_SUCCESS,
                    });
                } else {
                    res.send({
                        "status": 0,
                        "message": constant.USER_ALRD_RGST
                    });
                    return;
                }
            }
        });
    }
});


app.post("/changeMobileNo", function(req, res) {
    if (!req.body.user_pub_id || !req.body.country_code || !req.body.mobile_number) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        var user_id = req.body.user_pub_id;
        cm.getallDataWhere('user', {
            country_code: req.body.country_code,
            mobile_number: req.body.mobile_number
        }, function(err, result) {
            if (err) {
                console.log(err);
            } else {
                if (result.length == 0) {
                    cm.update('user', {
                        pub_id: user_id
                    }, {
                        country_code: req.body.country_code,
                        mobile_number: req.body.mobile_number
                    }, function(err, result) {
                        if (err) {
                            console.log(err);
                        } else {
                            cm.getallDataWhere('user', {
                                pub_id: user_id
                            }, function(err, result) {
                                if (err) {
                                    console.log(err);
                                } else {
                                    result[0].profile_image = base_url + result[0].profile_image;
                                    result[0].QR_image = base_url + result[0].QR_image;
                                    res.send({
                                        "status": 1,
                                        "message": constant.PROFILE_UPDATED,
                                        "data": result[0]
                                    });
                                }
                            });
                        }
                    })
                } else {
                    res.send({
                        "status": 0,
                        "message": constant.USER_ALRD_RGST
                    });
                    return;
                }
            }
        });
    }
});


app.post("/privatePublicProfile", function(req, res) {
    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        var user_id = req.body.user_pub_id;
        delete req.body.user_pub_id;
        delete req.body.language;
        cm.update('user', {
            pub_id: user_id
        }, req.body, function(err, result) {
            if (err) {
                console.log(err);
            } else {
                cm.getallDataWhere('user', {
                    pub_id: user_id
                }, function(err, result) {
                    if (err) {
                        console.log(err);
                    } else {

                        res.send({
                            "status": 1,
                            "message": constant.PROFILE_UPDATED,
                            "data": (typeof result[0] != "undefined") ? result[0] : {}
                        });
                    }
                });
            }
        })
    }
});

app.post("/updateDeviceToken", function(req, res) {
    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        var user_id = req.body.user_pub_id;
        delete req.body.user_pub_id;
        cm.update('user', {
            pub_id: user_id
        }, req.body, function(err, result) {
            if (err) {
                console.log(err);
            } else {
                cm.getallDataWhere('user', {
                    pub_id: user_id
                }, function(err, result) {
                    if (err) {
                        console.log(err);
                    } else {

                        res.send({
                            "status": 1,
                            "message": constant.PROFILE_UPDATED
                        });
                    }
                });
            }
        })
    }
});

app.post("/updateProfile", function(req, res) {
    req.body.is_private = 0;

    upload_image(req, res, function(err) {
        if (err, !req.files, !req.body.user_pub_id) {
            res.json({
                status: 0,
                message: constant.CHKAllFIELD
            });
            return;
        } else {
            if (!req.files[0]) {
                var user_id = req.body.user_pub_id;
                console.log("aaa", req.body);
                if (req.body.user_name) {
                    cm.getUserName(req.body.user_name, function(err, result) {
                        if (err) {
                            console.log(err);

                        } else {
                            if (result.length != 0) {
                                if (result[0].pub_id != user_id) {
                                    res.send({
                                        "status": 0,
                                        "message": constant.USERNAME_VALIDATION
                                    });
                                    return;
                                } else {
                                    delete req.body.user_pub_id;
                                    cm.update('user', {
                                        pub_id: user_id
                                    }, req.body, function(err, result) {
                                        if (err) {
                                            console.log(err);
                                        } else {
                                            cm.getallDataWhere('user', {
                                                pub_id: user_id
                                            }, function(err, result) {
                                                if (err) {
                                                    console.log(err);
                                                } else {
                                                    result[0].profile_image = base_url + result[0].profile_image;
                                                    result[0].QR_image = base_url + result[0].QR_image;
                                                    res.send({
                                                        "status": 1,
                                                        "message": constant.PROFILE_UPDATED,
                                                        "data": result[0]
                                                    });
                                                }
                                            });
                                        }
                                    })
                                }
                            } else {
                                delete req.body.user_pub_id;
                                cm.update('user', {
                                    pub_id: user_id
                                }, req.body, function(err, result) {
                                    if (err) {
                                        console.log(err);
                                    } else {
                                        cm.getallDataWhere('user', {
                                            pub_id: user_id
                                        }, function(err, result) {
                                            if (err) {
                                                console.log(err);
                                            } else {
                                                result[0].profile_image = base_url + result[0].profile_image;
                                                result[0].QR_image = base_url + result[0].QR_image;
                                                res.send({
                                                    "status": 1,
                                                    "message": constant.PROFILE_UPDATED,
                                                    "data": result[0]
                                                });
                                            }
                                        });
                                    }
                                })
                            }
                        }
                    });
                } else {
                    delete req.body.user_pub_id;
                    cm.update('user', {
                        pub_id: user_id
                    }, req.body, function(err, result) {
                        if (err) {
                            console.log(err);
                        } else {
                            cm.getallDataWhere('user', {
                                pub_id: user_id
                            }, function(err, result) {
                                if (err) {
                                    console.log(err);
                                } else {
                                    result[0].profile_image = base_url + result[0].profile_image;
                                    result[0].QR_image = base_url + result[0].QR_image;
                                    res.send({
                                        "status": 1,
                                        "message": constant.PROFILE_UPDATED,
                                        "data": result[0]
                                    });
                                }
                            });
                        }
                    })
                }
            } else {
                delete req.body.is_private;
                req.body.profile_image = "assets/images/profile/" + req.files[0].filename
                var user_id = req.body.user_pub_id;
                if (req.body.user_name) {
                    cm.getUserName(req.body.user_name, function(err, result) {
                        if (err) {
                            console.log(err);
                        } else {
                            if (result.length != 0) {
                                if (result[0].pub_id != user_id) {
                                    res.send({
                                        "status": 1,
                                        "message": constant.USERNAME_VALIDATION
                                    });
                                    return;
                                } else {
                                    delete req.body.user_pub_id;
                                    cm.update('user', {
                                        pub_id: user_id
                                    }, req.body, function(err, result) {
                                        if (err) {
                                            console.log(err);
                                        } else {
                                            cm.getallDataWhere('user', {
                                                pub_id: user_id
                                            }, function(err, result) {
                                                if (err) {
                                                    console.log(err);
                                                } else {
                                                    result[0].profile_image = base_url + result[0].profile_image;
                                                    result[0].QR_image = base_url + result[0].QR_image;
                                                    res.send({
                                                        "status": 1,
                                                        "message": constant.PROFILE_UPDATED,
                                                        "data": result[0]
                                                    });
                                                }
                                            });
                                        }
                                    })
                                }
                            } else {
                                delete req.body.user_pub_id;
                                cm.update('user', {
                                    pub_id: user_id
                                }, req.body, function(err, result) {
                                    if (err) {
                                        console.log(err);
                                    } else {
                                        cm.getallDataWhere('user', {
                                            pub_id: user_id
                                        }, function(err, result) {
                                            if (err) {
                                                console.log(err);
                                            } else {
                                                result[0].profile_image = base_url + result[0].profile_image;
                                                result[0].QR_image = base_url + result[0].QR_image;
                                                res.send({
                                                    "status": 1,
                                                    "message": constant.PROFILE_UPDATED,
                                                    "data": result[0]
                                                });
                                            }
                                        });
                                    }
                                })
                            }
                        }
                    });
                } else {
                    delete req.body.user_pub_id;
                    cm.update('user', {
                        pub_id: user_id
                    }, req.body, function(err, result) {
                        if (err) {
                            console.log(err);
                        } else {
                            cm.getallDataWhere('user', {
                                pub_id: user_id
                            }, function(err, result) {
                                if (err) {
                                    console.log(err);
                                } else {
                                    result[0].profile_image = base_url + result[0].profile_image;
                                    result[0].QR_image = base_url + result[0].QR_image;
                                    res.send({
                                        "status": 1,
                                        "message": constant.PROFILE_UPDATED,
                                        "data": result[0]
                                    });
                                }
                            });
                        }
                    })
                }
            }
        }
    });
});


app.post("/viewMyProfile", function(req, res) {

    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        var final_result = [];
        cm.getallDataWhere('user', {
            pub_id: req.body.user_pub_id
        }, function(err, chkUser) {
            if (chkUser.length == 0) {
                res.send({
                    status: 0,
                    message: constant.USER_NOT_FOUND
                });
            } else {
                cm.follower(req.body.user_pub_id, function(err, follower) {

                    chkUser[0].follower = follower.length;
                    chkUser[0].profile_image = base_url + chkUser[0].profile_image;
                    chkUser[0].QR_image = base_url + chkUser[0].QR_image;
                    final_result.push(follower);
                    cm.following(req.body.user_pub_id, function(err, following) {
                        chkUser[0].following = following.length;
                        cm.getallProductDataWhere('product', {
                            user_pub_id: req.body.user_pub_id,
                            status: 1
                        }, function(err, product) {
                            chkUser[0].following = following.length;
                            chkUser[0].total_product = product.length;

                            var productArr = [];
                            var productSoldArr = [];
                            if (product.length > 0) {
                                product
                                    .reduce(function(promiesRes, productdata, index) {
                                        return promiesRes
                                            .then(function(data) {
                                                return new Promise(function(resolve, reject) {
                                                    cm.getCategoryById(req.body.language, productdata.category_pub_id, function(err, category) {

                                                        if (category.length > 0) {
                                                            productdata.category_name = category[0].category_name;
                                                        } else {
                                                            productdata.category_name = "";
                                                        }
                                                        resolve(productdata);

                                                    })
                                                })
                                            })
                                            .then(function(data) {

                                                return new Promise(function(resolve, reject) {
                                                    cm.getCategoryById(req.body.language, productdata.sub_cat_pub_id, function(err, sub_category) {
                                                        if (sub_category.length > 0) {
                                                            productdata.sub_category_name = sub_category[0].category_name;
                                                        } else {
                                                            productdata.sub_category_name = "";
                                                        }
                                                        resolve(productdata);

                                                    })
                                                })
                                            })
                                            .then(function(data) {
                                                return new Promise(function(resolve, reject) {
                                                    cm.getBrandById(req.body.language, productdata.car_brand_pub_id, function(err, car_brand) {

                                                        if (car_brand.length > 0) {
                                                            productdata.car_brand_name = car_brand[0].brand_name;
                                                        } else {
                                                            productdata.car_brand_name = "";
                                                        }
                                                        resolve(productdata);
                                                    })
                                                })
                                            })
                                            .then(function(data) {
                                                return new Promise(function(resolve, reject) {
                                                    cm.getModelById(req.body.language, productdata.car_model_pub_id, function(err, car_model) {
                                                        if (car_model.length > 0) {
                                                            productdata.car_model_name = car_model[0].model_name;
                                                        } else {
                                                            productdata.car_model_name = "";
                                                        }
                                                        resolve(productdata);
                                                    })
                                                })
                                            })
                                            .then(function(productdata) {

                                                return new Promise(function(resolve, reject) {
                                                    cm.getallDataWhere('likes_views', {
                                                        user_pub_id: req.body.user_pub_id,
                                                        product_pub_id: productdata.pub_id,
                                                        type: 1,
                                                    }, function(err, likes) {
                                                        console.log(err);

                                                        if (likes.length == 0) {
                                                            productdata.isLike = "0";
                                                        } else {
                                                            productdata.isLike = "1";
                                                        }
                                                        resolve(productdata);
                                                    })
                                                })
                                            })
                                            .then(function(productdata) {

                                                return new Promise(function(resolve, reject) {
                                                    cm.getallDataWhere('comments', {
                                                        product_pub_id: productdata.pub_id
                                                    }, function(err, comments) {

                                                        productdata.getCommentsCount = comments.length;
                                                        resolve(productdata);
                                                    })
                                                })
                                            })
                                            .then(function(productdata) {

                                                return new Promise(function(resolve, reject) {
                                                    cm.getallDataWhere('likes_views', {
                                                        product_pub_id: productdata.pub_id,
                                                        type: 1,
                                                    }, function(err, allLikes) {

                                                        productdata.getLikesCount = allLikes.length;
                                                        resolve(productdata);
                                                    })
                                                })
                                            })
                                            .then(function(productdata) {

                                                return new Promise(function(resolve, reject) {
                                                    cm.getallDataWhere('likes_views', {
                                                        product_pub_id: productdata.pub_id,
                                                        type: 2,
                                                    }, function(err, view_result) {
                                                        productdata.getViewCount = view_result.length;
                                                        resolve(productdata);
                                                    });
                                                })
                                            })
                                            .then(function(productdata) {

                                                return new Promise(function(resolve, reject) {
                                                    cm.getallDataWhere('forward', {
                                                        product_pub_id: productdata.pub_id
                                                    }, function(err, forword_result) {
                                                        productdata.getForwordCount = forword_result.length;
                                                        resolve(productdata);
                                                    });
                                                })
                                            })
                                            .then(function(productdata) {

                                                return new Promise(function(resolve, reject) {
                                                    cm.getLikeUsers(productdata.pub_id, function(err, like_users) {

                                                        productdata.getLikesuser = like_users;
                                                        resolve(productdata);
                                                    })
                                                })
                                            })
                                            .then(function(productdata) {

                                                return new Promise(function(resolve, reject) {
                                                    cm.getCommentsUsers(productdata.pub_id, function(err, commented_user) {

                                                        productdata.getCommentedUsers = commented_user;
                                                        resolve(productdata);
                                                    })
                                                })
                                            })
                                            .then(function(productdata) {

                                                return new Promise(function(resolve, reject) {
                                                    cm.getMediaDatails(productdata.pub_id, function(err, mediaData) {

                                                        productdata.media = mediaData;

                                                        if (productdata.is_sold == 0) {
                                                            productSoldArr.push(productdata);
                                                        } else {
                                                            productArr.push(productdata);
                                                        }
                                                        resolve(productdata);

                                                    })
                                                })
                                            })
                                            .catch(function(error) {
                                                console.log(' -- error: ', error);
                                                res.send({
                                                    "status": 0,
                                                    "message": constant.ERR
                                                });
                                                return error.message;
                                            })
                                    }, Promise.resolve(null)).then(arrayOfResults => { // Do something with all results

                                        chkUser[0].product = productArr.reverse();
                                        chkUser[0].sold_product = productSoldArr.reverse();
                                        res.send({
                                            "status": 1,
                                            "message": constant.PRODUCTS,
                                            "data": chkUser[0]
                                        });
                                    });
                            } else {
                                chkUser[0].product = productArr.reverse();
                                chkUser[0].sold_product = productSoldArr.reverse();
                                res.send({
                                    "status": 1,
                                    "message": constant.PRODUCTS,
                                    "data": chkUser[0]
                                });
                            }
                        });
                    });
                });
            }
        })
    }
});

app.post("/viewOthersProfile", function(req, res) {

    if (!req.body.user_pub_id || !req.body.friend_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        var final_result = [];
        cm.getallDataWhere('user', {
            pub_id: req.body.friend_pub_id
        }, function(err, chkUser) {
            if (chkUser.length == 0) {
                res.send({
                    status: 0,
                    message: constant.USER_NOT_FOUND
                });
            } else {
                cm.getallDataWhere('followers', {
                    following_user_pub_id: req.body.friend_pub_id,
                    user_pub_id: req.body.user_pub_id
                }, function(err, followers) {
                    if (followers.length > 0) {
                        chkUser[0].is_follower = "1";
                    } else {
                        chkUser[0].is_follower = "0";
                    }
                    cm.getallDataWhere('followers', {
                        following_user_pub_id: req.body.user_pub_id,
                        user_pub_id: req.body.friend_pub_id
                    }, function(err, follows) {
                        if (follows.length > 0) {
                            chkUser[0].is_following = "1";
                        } else {
                            chkUser[0].is_following = "0";
                        }
                        cm.follower(req.body.friend_pub_id, function(err, follower) {
                            console.log(err);
                            chkUser[0].follower = follower.length;
                            chkUser[0].profile_image = base_url + chkUser[0].profile_image;
                            chkUser[0].QR_image = base_url + chkUser[0].QR_image;
                            final_result.push(follower);
                            cm.following(req.body.friend_pub_id, function(err, following) {
                                chkUser[0].following = following.length;
                                cm.getallProductDataWhere('product', {
                                    user_pub_id: req.body.friend_pub_id,
                                    status: 1
                                }, function(err, product) {
                                    chkUser[0].following = following.length;
                                    chkUser[0].total_product = product.length;

                                    var productArr = [];
                                    var productSoldArr = [];
                                    if (product.length > 0) {
                                        product
                                            .reduce(function(promiesRes, productdata, index) {
                                                return promiesRes
                                                    .then(function(data) {
                                                        return new Promise(function(resolve, reject) {
                                                            cm.getCategoryById(req.body.language, productdata.category_pub_id, function(err, category) {
                                                                if (category.length > 0) {
                                                                    productdata.category_name = category[0].category_name;
                                                                } else {
                                                                    productdata.category_name = '';
                                                                }
                                                                resolve(productdata);
                                                            })
                                                        })
                                                    })
                                                    .then(function(productdata) {
                                                        return new Promise(function(resolve, reject) {
                                                            cm.getallDataWhere('user', {
                                                                pub_id: req.body.friend_pub_id
                                                            }, function(err, is_user) {
                                                                if (is_user.length != 0) {
                                                                    productdata.userImage = base_url + is_user[0].profile_image;
                                                                    productdata.userName = is_user[0].user_name;
                                                                    productdata.profile_name = is_user[0].name;
                                                                } else {
                                                                    productdata.userImage = '';
                                                                    productdata.userName = '';
                                                                    productdata.profile_name = '';
                                                                }

                                                                resolve(productdata);

                                                            })
                                                        })
                                                    })
                                                    .then(function(productdata) {

                                                        return new Promise(function(resolve, reject) {
                                                            cm.getallDataWhere('likes_views', {
                                                                user_pub_id: req.body.friend_pub_id,
                                                                product_pub_id: productdata.pub_id,
                                                                type: 1,
                                                            }, function(err, likes) {

                                                                if (likes.length == 0) {
                                                                    productdata.isLike = '0';
                                                                } else {
                                                                    productdata.isLike = '1';
                                                                }

                                                                resolve(productdata);

                                                            })
                                                        })
                                                    })
                                                    .then(function(productdata) {

                                                        return new Promise(function(resolve, reject) {
                                                            cm.getallDataWhere('comments', {
                                                                product_pub_id: productdata.pub_id
                                                            }, function(err, comments) {

                                                                productdata.getCommentsCount = comments.length;

                                                                resolve(productdata);

                                                            })
                                                        })
                                                    })
                                                    .then(function(productdata) {

                                                        return new Promise(function(resolve, reject) {
                                                            cm.getallDataWhere('likes_views', {
                                                                product_pub_id: productdata.pub_id,
                                                                type: 1,
                                                            }, function(err, allLikes) {

                                                                productdata.getLikesCount = allLikes.length;


                                                                resolve(productdata);

                                                            })
                                                        })
                                                    })
                                                    .then(function(productdata) {

                                                        return new Promise(function(resolve, reject) {
                                                            cm.getallDataWhere('likes_views', {
                                                                product_pub_id: productdata.pub_id,
                                                                type: 2,
                                                            }, function(err, view_result) {
                                                                productdata.getViewCount = view_result.length;
                                                                resolve(productdata);
                                                            });
                                                        })
                                                    })
                                                    .then(function(productdata) {

                                                        return new Promise(function(resolve, reject) {
                                                            cm.getallDataWhere('forward', {
                                                                product_pub_id: productdata.pub_id
                                                            }, function(err, forword_result) {
                                                                productdata.getForwordCount = forword_result.length;
                                                                resolve(productdata);
                                                            });
                                                        })
                                                    })
                                                    .then(function(productdata) {

                                                        return new Promise(function(resolve, reject) {
                                                            cm.getMediaDatails(productdata.pub_id, function(err, mediaData) {

                                                                productdata.media = mediaData;
                                                                if (productdata.is_sold == 0) {
                                                                    productSoldArr.push(productdata);
                                                                } else {
                                                                    productArr.push(productdata);
                                                                }
                                                                //productArr.push(productdata);
                                                                resolve(productdata);

                                                            })
                                                        })
                                                    })
                                                    .catch(function(error) {
                                                        console.log(' -- error: ', error);
                                                        res.send({
                                                            "status": 0,
                                                            "message": 'Internal Error'
                                                        });
                                                        return error.message;
                                                    })
                                            }, Promise.resolve(null)).then(arrayOfResults => { // Do something with all results
                                                var mm_message = constant.PROFILE_USER_PRODUCT;
                                                /*if(chkUser[0].is_private == 1){
                                                    chkUser[0].product = [];
                                                    chkUser[0].sold_product = [];
                                                    mm_message = constant.PROFILE_NO_USER_PRODUCT;
                                                }else{*/
                                                chkUser[0].product = productArr.reverse();
                                                chkUser[0].sold_product = productSoldArr.reverse();
                                                //}

                                                res.send({
                                                    "status": 1,
                                                    "message": mm_message,
                                                    "data": chkUser[0],
                                                    "is_private": chkUser[0].is_private
                                                });
                                            });
                                    } else {
                                        chkUser[0].product = productArr.reverse();
                                        chkUser[0].sold_product = productSoldArr.reverse();
                                        res.send({
                                            "status": 1,
                                            "message": constant.PRODUCTS,
                                            "data": chkUser[0],
                                            "is_private": chkUser[0].is_private
                                        });
                                    }
                                });
                            });

                        });
                    });
                });
            }
        })
    }
});
app.post("/sendmsg", function(req, res) {

    upload_chat(req, res, function(err) {
        if (err, !req.files) {
            res.json({
                status: 0,
                message: constant.CHKAllFIELD
            });
            return;
        } else {

            cm.getSinglerow('user', "pub_id='" + req.body.user_pub_id + "'", function(err, result) {
                if (result.length == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.USER_NOT_FOUND
                    });
                    return;
                }
            });
            cm.getSinglerow('user', "pub_id='" + req.body.user_pub_id_receiver + "'", function(err, result) {
                if (result.length == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.USER_NOT_FOUND
                    });
                    return;
                }
            });


            cm.getallDataWhere('block_list', {
                user_pub_id: req.body.user_pub_id,
                block_user_pub_id: req.body.user_pub_id_receiver
            }, function(err, blockStatus) {
                if (blockStatus.length == 0) {
                    cm.getallDataWhere('block_list', {
                        user_pub_id: req.body.user_pub_id_receiver,
                        block_user_pub_id: req.body.user_pub_id
                    }, function(err, blockStatus2) {
                        if (blockStatus2.length == 0) {
                            var edate = (new Date()).valueOf().toString();
                            req.body.date = edate

                            if (!req.files[0]) {
                                req.body.media = ""
                                delete req.body.language;
                                delete req.body.sender_name;
                                cm.insert('chat', req.body, function(err, result) {
                                    console.log(err);
                                    if (err) {

                                        res.send({
                                            "status": 0,
                                            "message": constant.ERR
                                        });
                                    } else {
                                        res.send({
                                            "status": 1,
                                            "message": constant.MSGSENDSUCCESS
                                        });
                                        cm.getallDataWhere('user', {
                                            pub_id: req.body.user_pub_id_receiver
                                        }, function(err, result) {
                                            if (err) {
                                                console.log(err);
                                            } else {

                                                cm.getMyUnreadCount(req.body.user_pub_id_receiver, function(err, chats) {
                                                    var this_socket = io.users[req.body.user_pub_id_receiver];
                                                    //console.log("user status", this_socket);
                                                    if (typeof this_socket != "undefined") {
                                                        var up_data = {
                                                            unread_counts: chats.length
                                                        }

                                                        this_socket.emit("chat_user_counts", up_data);
                                                    }
                                                });

                                                var receiver_data = JSON.parse(JSON.stringify(result[0]));
                                                var receiver_token = receiver_data.device_token
                                                cm.getallDataWhere('user', {
                                                    pub_id: req.body.user_pub_id
                                                }, function(err, result) {
                                                    if (err) {
                                                        console.log(err);
                                                    } else {
                                                        var user_data = JSON.parse(JSON.stringify(result[0]));
                                                        var user_name = user_data.name;
                                                        var element = {};
                                                        var chatData1 = {};
                                                        element.title = user_name;
                                                        element.type = req.body.me;
                                                        element.sender_id = req.body.user_pub_id;
                                                        element.sender_name = user_name;
                                                        element.body = req.body.message;
                                                        chatData1.data = element;
                                                        var chatData = JSON.stringify(chatData1);
                                                        // cm.pushnotificationV2(user_name, req.body.message, receiver_token,chatData, '70001');
                                                        var msg = user_name + ": " + req.body.message;
                                                        cm.pushnotificationChat(user_name, msg, receiver_token, req.body.user_pub_id, '70001');
                                                    }
                                                });
                                            }
                                        });
                                    }

                                });
                            } else {
                                req.body.media = "assets/chat_media/" + req.files[0].filename;
                                delete req.body.language;
                                delete req.body.sender_name;
                                cm.insert('chat', req.body, function(err, result) {
                                    if (err) {
                                        console.log(err);
                                        res.send({
                                            "status": 0,
                                            "message": constant.ERR
                                        });
                                    } else {
                                        res.send({
                                            "status": 1,
                                            "message": constant.MSGSENDSUCCESS
                                        });
                                        cm.getallDataWhere('user', {
                                            pub_id: req.body.user_pub_id_receiver
                                        }, function(err, result) {
                                            if (err) {
                                                console.log(err);
                                            } else {
                                                var receiver_data = JSON.parse(JSON.stringify(result[0]));
                                                var receiver_token = receiver_data.device_token
                                                cm.getallDataWhere('user', {
                                                    pub_id: req.body.user_pub_id
                                                }, function(err, result) {
                                                    if (err) {
                                                        console.log(err);
                                                    } else {
                                                        var user_data = JSON.parse(JSON.stringify(result[0]));
                                                        var user_name = user_data.name;
                                                        cm.pushnotificationChat(user_name, user_name + ': Image', receiver_token, req.body.user_pub_id, '70001');

                                                    }
                                                });
                                            }
                                        });
                                    }

                                });
                            }
                        } else {
                            cm.getallDataWhere('user', {
                                pub_id: req.body.user_pub_id_receiver
                            }, function(err, userData) {
                                res.send({
                                    "status": 6,
                                    "message": userData[0].name + constant.BLOCK_MSG
                                });
                            });
                        }
                    });
                } else {
                    cm.getallDataWhere('user', {
                        pub_id: req.body.user_pub_id_receiver
                    }, function(err, userData) {

                        res.send({
                            "status": 5,
                            "message": constant.PLEASE_UNBLOCK + userData[0].name + constant.UNBLOCK_MESG
                        });
                    });
                }
            });
        }
    });
});

app.post("/addCallData", function(req, res) {

    cm.getSinglerow('user', "pub_id='" + req.body.user_pub_id + "'", function(err, result) {
        if (result.length == 0) {
            res.send({
                "status": 0,
                "message": constant.USER_NOT_FOUND
            });
        } else {
            cm.getSinglerow('user', "pub_id='" + req.body.user_pub_id_receiver + "'", function(err, result) {
                if (result.length == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.USER_NOT_FOUND
                    });
                } else {
                    cm.getallDataWhere('block_list', {
                        user_pub_id: req.body.user_pub_id,
                        block_user_pub_id: req.body.user_pub_id_receiver
                    }, function(err, blockStatus) {
                        if (blockStatus.length == 0) {
                            cm.getallDataWhere('block_list', {
                                user_pub_id: req.body.user_pub_id_receiver,
                                block_user_pub_id: req.body.user_pub_id
                            }, function(err, blockStatus2) {
                                if (blockStatus2.length == 0) {
                                    var edate = (new Date()).valueOf().toString();
                                    req.body.date = edate;
                                    req.body.media = "";
                                    delete req.body.language;
                                    delete req.body.sender_name;
                                    cm.insert('chat', req.body, function(err, result) {
                                        console.log(err);
                                        if (err) {
                                            /*res.send({
                                                "status": 0,
                                                "message": constant.ERR
                                            });*/
                                        } else {
                                            res.send({
                                                "status": 1,
                                                "message": constant.MSGSENDSUCCESS
                                            });
                                            cm.getallDataWhere('user', {
                                                pub_id: req.body.user_pub_id_receiver
                                            }, function(err, result) {
                                                if (err) {
                                                    console.log(err);
                                                } else {
                                                    var receiver_data = JSON.parse(JSON.stringify(result[0]));
                                                    var receiver_token = receiver_data.device_token
                                                    cm.getallDataWhere('user', {
                                                        pub_id: req.body.user_pub_id
                                                    }, function(err, result) {
                                                        if (err) {
                                                            console.log(err);
                                                        } else {
                                                            /*var user_data = JSON.parse(JSON.stringify(result[0]));
                                                            var user_name = user_data.name;
                                                            var element = {};
                                                            var chatData1 = {};
                                                            element.title = user_name;
                                                            element.type = req.body.me;
                                                            element.sender_id = req.body.user_pub_id;
                                                            element.sender_name = user_name;
                                                            element.body = req.body.message;
                                                            chatData1.data=element;
                                                            var chatData= JSON.stringify(chatData1);
                                                            // cm.pushnotificationV2(user_name, req.body.message, receiver_token,chatData, '70001');
                                                            var msg = user_name+ ": "+ req.body.message;
                                                            cm.pushnotificationChat(user_name, msg, receiver_token,req.body.user_pub_id, '70001');*/
                                                        }
                                                    });
                                                }
                                            });
                                        }

                                    });

                                } else {
                                    cm.getallDataWhere('user', {
                                        pub_id: req.body.user_pub_id_receiver
                                    }, function(err, userData) {
                                        res.send({
                                            "status": 6,
                                            "message": userData[0].name + constant.BLOCK_MSG
                                        });
                                    });
                                }
                            });
                        } else {
                            cm.getallDataWhere('user', {
                                pub_id: req.body.user_pub_id_receiver
                            }, function(err, userData) {

                                res.send({
                                    "status": 5,
                                    "message": constant.PLEASE_UNBLOCK + userData[0].name + constant.UNBLOCK_MESG
                                });
                            });
                        }
                    });
                }
            });
        }
    });





});

app.post("/getChatHistory", function(req, res) {
    if (req.body.language == 'AR') {
        constant = constantAR;
    }
    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getSinglerow('user', "pub_id='" + req.body.user_pub_id + "'", function(err, result) {
            if (result.length == 0) {
                res.send({
                    "status": 0,
                    "message": constant.USER_NOT_FOUND
                });
            } else {
                cm.getChatHistory(req.body.user_pub_id, function(err, chat_result) {
                    var chat_row = [];
                    if (err) {
                        res.send({
                            "status": 0,
                            "message": constant.NO_CHAT
                        });
                    } else
                    if (chat_result.length == 0) {
                        var final_result = [];
                        final_result = _.uniqBy(chat_row, 'user_pub_id_receiver');

                        cm.getAdminChat(function(err, admin_chat) {
                            if (admin_chat != 0) {
                                admin_chat[0].unReadMsg = 0;
                                admin_chat[0].isBlock = "0";
                                admin_chat[0].is_follow = "0";
                                admin_chat[0].online_status = 1;
                                admin_chat[0].user_pub_id = "KEYMARKETSUPER";
                                admin_chat[0].userStatus = "0";
                                admin_chat[0].name = "KeyMarket Team";
                                admin_chat[0].userName = "keymarket_team";
                                admin_chat[0].userImage = base_url + "assets/images/profile/logo.jpg";

                            } else {
                                var admin_chat = Array();
                            }
                            /*For admin chat uncomment this line*/
                            final_result.unshift(admin_chat[0]);

                            res.send({
                                "status": 1,
                                "message": constant.CHAT_HST,
                                "my_chat": final_result
                            });
                        });

                        /*res.send({
                            "status": 0,
                            "message": constant.NO_CHAT
                        });*/
                    } else {
                        var chat_row_arr = {};


                        chat_result
                            .reduce(function(promiesRes, chatdata, index) {
                                return promiesRes

                                    .then(function(data) {

                                        return new Promise(function(resolve, reject) {
                                            if (req.body.user_pub_id == chatdata.user_pub_id_receiver) {
                                                user_pub_id = chatdata.user_pub_id;
                                                chatdata.user_pub_id_receiver = chatdata.user_pub_id;
                                            } else {
                                                user_pub_id = chatdata.user_pub_id_receiver;
                                            }

                                            cm.getallDataWhere('user', {
                                                pub_id: user_pub_id
                                            }, function(err, result1) {
                                                if (result1.length > 0) {
                                                    if (result1[0].thumb)
                                                        chatdata.thumb = base_url + result1[0].thumb;
                                                    chatdata.userName = result1[0].user_name;
                                                    chatdata.name = result1[0].name;
                                                    chatdata.user_pub_id = result1[0].pub_id;
                                                    chatdata.userImage = base_url + result1[0].profile_image;
                                                    chatdata.online_status = result1[0].online_status;
                                                }
                                                resolve(chatdata);
                                            })
                                        })
                                    })
                                    .then(function(chatdata) {

                                        return new Promise(function(resolve, reject) {
                                            cm.getUnreadCount(req.body.user_pub_id, chatdata.user_pub_id_receiver, function(err, unread) {
                                                chatdata.unReadMsg = unread.length;
                                                resolve(chatdata);
                                            })
                                        })
                                    })
                                    .then(function(chatdata) {

                                        return new Promise(function(resolve, reject) {
                                            cm.blockStatus(req.body.user_pub_id, chatdata.user_pub_id_receiver, function(err, blockstatus) {
                                                if (blockstatus.length > 0) {
                                                    chatdata.isBlock = '1';
                                                } else {
                                                    chatdata.isBlock = '0';
                                                }
                                                resolve(chatdata);
                                            })
                                        })
                                    })
                                    .then(function(chatdata) {

                                        return new Promise(function(resolve, reject) {
                                            cm.getallDataWhere('followers', {
                                                user_pub_id: req.body.user_pub_id,
                                                following_user_pub_id: chatdata.user_pub_id_receiver
                                            }, function(err, followers) {
                                                if (followers.length > 0) {
                                                    chatdata.is_follow = "1";
                                                } else {
                                                    chatdata.is_follow = "0";
                                                }
                                                resolve(chatdata);
                                            })
                                        })
                                    })
                                    .then(function(chatdata) {

                                        return new Promise(function(resolve, reject) {
                                            cm.getallDataWhere('user', {
                                                pub_id: chatdata.user_pub_id_receiver
                                            }, function(err, user_mode) {
                                                if (user_mode.length > 0 && user_mode[0].user_mode == 1) {
                                                    chatdata.userStatus = '1';
                                                } else {
                                                    chatdata.userStatus = '0';
                                                }

                                                resolve(chatdata);

                                            })
                                        })
                                    })
                                    .then(function(chatdata) {

                                        return new Promise(function(resolve, reject) {
                                            cm.getChatData_blank(req.body.user_pub_id, chatdata.user_pub_id_receiver, function(err, blankchat) {
                                                if (blankchat.length > 0) {
                                                    if (chatdata.user_pub_id_receiver != req.body.user_pub_id)
                                                        chat_row.push(chatdata);
                                                    resolve(chatdata);
                                                } else {
                                                    resolve(chatdata);
                                                }
                                            });
                                        })
                                    })
                                    .catch(function(error) {

                                        res.send({
                                            "status": 0,
                                            "message": constant.INTERNAL_ERROR
                                        });
                                        return error.message;
                                    })
                            }, Promise.resolve(null)).then(arrayOfResults => { // Do something with all results
                                var final_result = [];
                                final_result = _.uniqBy(chat_row, 'user_pub_id_receiver');

                                cm.getAdminChat(function(err, admin_chat) {
                                    if (admin_chat != 0) {
                                        admin_chat[0].unReadMsg = 0;
                                        admin_chat[0].isBlock = "0";
                                        admin_chat[0].is_follow = "0";
                                        admin_chat[0].user_pub_id = "KEYMARKETSUPER";
                                        admin_chat[0].userStatus = "0";
                                        admin_chat[0].online_status = 1;
                                        admin_chat[0].userName = "keymarket_team";
                                        admin_chat[0].name = "KeyMarket Team";
                                        admin_chat[0].userImage = base_url + "assets/images/profile/logo.jpg";
                                    } else {
                                        var admin_chat = Array();
                                    }
                                    /*For admin chat uncomment this line*/
                                    final_result.unshift(admin_chat[0]);

                                    res.send({
                                        "status": 1,
                                        "message": constant.CHAT_HST,
                                        "my_chat": final_result
                                    });
                                });
                            });
                    }
                });
            }
        });
    }

});

app.post("/getCallHistory", function(req, res) {
    if (req.body.language == '2') {
        constant = constantAR;
    }
    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getSinglerow('user', "pub_id='" + req.body.user_pub_id + "'", function(err, result) {
            if (result.length == 0) {
                res.send({
                    "status": 0,
                    "message": constant.USER_NOT_FOUND
                });
            } else {
                cm.getCallHistory(req.body.user_pub_id, function(err, chat_result) {
                    var chat_row = [];
                    if (err) {
                        res.send({
                            "status": 0,
                            "message": constant.NO_CALL
                        });
                    } else
                    if (chat_result.length == 0) {
                        res.send({
                            "status": 1,
                            "message": constant.NO_CALL
                        });
                    } else {
                        var chat_row_arr = {};

                        chat_result
                            .reduce(function(promiesRes, chatdata, index) {
                                return promiesRes

                                    .then(function(data) {

                                        return new Promise(function(resolve, reject) {
                                            if (req.body.user_pub_id == chatdata.user_pub_id_receiver) {
                                                user_pub_id = chatdata.user_pub_id;
                                                chatdata.user_pub_id_receiver = chatdata.user_pub_id;
                                            } else {
                                                user_pub_id = chatdata.user_pub_id_receiver;
                                            }

                                            cm.getallDataWhere('user', {
                                                pub_id: user_pub_id
                                            }, function(err, result1) {
                                                if (result1.length > 0) {
                                                    if (result1[0].thumb)
                                                        chatdata.thumb = base_url + result1[0].thumb;
                                                    chatdata.userName = result1[0].user_name;
                                                    chatdata.name = result1[0].name;
                                                    chatdata.user_pub_id = result1[0].pub_id;
                                                    chatdata.userImage = base_url + result1[0].profile_image;
                                                    chatdata.online_status = result1[0].online_status;
                                                }
                                                resolve(chatdata);
                                            })
                                        })
                                    })
                                    .then(function(chatdata) {
                                        return new Promise(function(resolve, reject) {
                                            cm.blockStatus(req.body.user_pub_id, chatdata.user_pub_id_receiver, function(err, blockstatus) {
                                                if (blockstatus.length > 0) {
                                                    chatdata.isBlock = '1';
                                                } else {
                                                    chatdata.isBlock = '0';
                                                }
                                                resolve(chatdata);
                                            })
                                        })
                                    })
                                    .then(function(chatdata) {
                                        return new Promise(function(resolve, reject) {
                                            cm.getallDataWhere('followers', {
                                                user_pub_id: req.body.user_pub_id,
                                                following_user_pub_id: chatdata.user_pub_id_receiver
                                            }, function(err, followers) {
                                                if (followers.length > 0) {
                                                    chatdata.is_follow = "1";
                                                } else {
                                                    chatdata.is_follow = "0";
                                                }
                                                resolve(chatdata);
                                            })
                                        })
                                    })
                                    .then(function(chatdata) {
                                        return new Promise(function(resolve, reject) {
                                            cm.getallDataWhere('user', {
                                                pub_id: chatdata.user_pub_id_receiver
                                            }, function(err, user_mode) {
                                                if (user_mode.length > 0 && user_mode[0].user_mode == 1) {
                                                    chatdata.userStatus = '1';
                                                } else {
                                                    chatdata.userStatus = '0';
                                                }

                                                resolve(chatdata);

                                            })
                                        })
                                    })
                                    .then(function(chatdata) {

                                        return new Promise(function(resolve, reject) {
                                            cm.getChatData_blank(req.body.user_pub_id, chatdata.user_pub_id_receiver, function(err, blankchat) {
                                                if (blankchat.length > 0) {
                                                    if (chatdata.user_pub_id_receiver != req.body.user_pub_id)
                                                        chat_row.push(chatdata);
                                                    resolve(chatdata);
                                                } else {
                                                    resolve(chatdata);
                                                }
                                            });
                                        })
                                    })
                                    .catch(function(error) {

                                        res.send({
                                            "status": 0,
                                            "message": constant.INTERNAL_ERROR
                                        });
                                        return error.message;
                                    })
                            }, Promise.resolve(null)).then(arrayOfResults => { // Do something with all results
                                var final_result = [];
                                //final_result = _.uniqBy(chat_row, 'user_pub_id_receiver');
                                final_result = chat_row;
                                res.send({
                                    "status": 1,
                                    "message": constant.CHAT_HST,
                                    "my_chat": final_result
                                });
                            });
                    }
                });
            }
        });
    }

});

app.post("/getChat", function(req, res) {
    if (!req.body.sender_id || !req.body.receiver_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {

        if (req.body.receiver_id == "KEYMARKETSUPER") {
            cm.getAdminChatV1(function(err, result) {
                if (result.length > 0) {
                    var chatresult = [];
                    var user_data = {};
                    result.forEach(function(result1) {
                        if (result1.chat_type == 3 && result1.calling_status == 1) {
                            result1.message = constant.ENDEDVIDEOCHAT;
                        }
                        chatresult.push(result1);
                    });
                    cm.getUserById(req.body.receiver_id, function(err, data) {
                        data = data[0];
                        //console.log(data);
                        user_data.name = data.name;
                        user_data.user_name = data.user_name;
                        //user_data.profile_img = base_url+data.profile_image;
                        user_data.profile_img = base_url + "assets/images/profile/logo.jpg";
                        user_data.pub_id = data.pub_id;
                        user_data.online_status = data.online_status;
                        res.send({
                            "status": 1,
                            "message": constant.MY_CONVERSION,
                            "my_chat": chatresult,
                            "user_data": user_data
                        });
                    });

                } else {
                    res.send({
                        "status": 0,
                        "message": constant.NO_CHAT
                    });
                }
            });
        } else {
            cm.markChatRead(req.body.sender_id, req.body.receiver_id, function(err, markdata) {
                cm.getMyUnreadCount(req.body.sender_id, function(err, chats) {
                    var this_socket = io.users[req.body.sender_id];
                    //console.log("user status", this_socket);
                    if (typeof this_socket != "undefined") {
                        var up_data = {
                                unread_counts: chats.length
                            }
                            //console.log("after mark read",up_data);
                        this_socket.emit("chat_user_counts", up_data);
                    }
                });
            });
            cm.getChatData(req.body.sender_id, req.body.receiver_id, function(err, result) {
                if (result.length > 0) {
                    var chatresult = [];
                    var user_data = {};
                    result.reduce(function(promiesRes, result1, index) {

                        return promiesRes
                            .then(function(userMediaRes) {
                                //result.forEach(function(result1) {
                                return new Promise(function(resolve, reject) {
                                    if (result1.chat_type == 3 && result1.calling_status == 0) {
                                        result1.message = constant.STRATEDVIDEOCHAT;
                                    }
                                    if (result1.chat_type == 3 && result1.calling_status == 1) {
                                        result1.message = constant.ENDEDVIDEOCHAT;
                                    }
                                    if (result1.chat_type == 2) {
                                        result1.media = base_url + result1.media;
                                    }

                                    if (result1.chat_type == 4) {
                                        result1.media = base_url + result1.media;

                                        cm.getallDataWhere('user', {
                                                pub_id: result1.media_owner_pub_id
                                            },
                                            function(err, user_result) {
                                                if (user_result.length > 0) {
                                                    var temp_user = user_result[0].user_name;
                                                    owner_name = temp_user;
                                                } else {
                                                    owner_name = "";
                                                }
                                            });
                                        result1.owner_name = owner_name;
                                    }
                                    resolve(result1);
                                });
                            }).then(function(media) {
                                return new Promise(function(resolve, reject) {
                                    cm.getUserById(req.body.receiver_id, function(err, data) {
                                        data = data[0];
                                        //console.log(data);
                                        user_data.name = data.name;
                                        user_data.user_name = data.user_name;
                                        user_data.profile_img = base_url + data.profile_image;
                                        user_data.pub_id = data.pub_id;
                                        user_data.online_status = data.online_status;
                                        resolve(result1);
                                    });

                                });
                            }).then(function(media) {
                                return new Promise(function(resolve, reject) {
                                    cm.blockStatus(req.body.receiver_id, req.body.sender_id, function(err, data) {
                                        if (data.length == 0) {
                                            user_data.is_block = 0;
                                        } else {
                                            user_data.is_block = 1;
                                        }
                                        resolve(result1);
                                    });
                                });
                            }).then(function(media) {
                                return new Promise(function(resolve, reject) {
                                    cm.followStatus(req.body.receiver_id, req.body.sender_id, function(err, data) {
                                        //console.log(err);
                                        if (data.length == 0) {
                                            user_data.is_following = 0;
                                        } else {
                                            user_data.is_following = 1;
                                        }
                                        resolve(result1);
                                    });
                                });
                            }).then(function(data) {


                                chatresult.push(result1);

                            })
                            .catch(function(error) {
                                console.log(error);
                                res.send({
                                    "status": 0,
                                    "message": constant.INTERNAL_ERROR
                                });
                                return error.message;
                            });
                    }, Promise.resolve(null)).then(arrayOfResults => {

                        res.send({
                            "status": 1,
                            "message": constant.MY_CONVERSION,
                            "my_chat": chatresult,
                            "user_data": user_data
                        });
                    });
                } else {
                    // return new Promise(function(resolve, reject) {
                    var user_data = {};
                    cm.getUserById(req.body.receiver_id, function(err, data) {
                        data = data[0];
                        //console.log(data);
                        user_data.name = data.name;
                        user_data.user_name = data.user_name;
                        user_data.profile_img = base_url + data.profile_image;
                        user_data.online_status = data.online_status;
                        user_data.pub_id = data.pub_id;
                        cm.followStatus(req.body.receiver_id, req.body.sender_id, function(err, data) {
                            //console.log(err);
                            if (data.length == 0) {
                                user_data.is_following = 0;
                            } else {
                                user_data.is_following = 1;
                            }

                            cm.blockStatus(req.body.receiver_id, req.body.sender_id, function(err, data) {
                                if (data.length == 0) {
                                    user_data.is_block = 0;
                                } else {
                                    user_data.is_block = 1;
                                }
                                res.send({
                                    "status": 1,
                                    "message": constant.NO_CHAT,
                                    "user_data": user_data
                                });

                            });
                        });


                    });
                    // });
                }
            });
        }
    }
});

app.post('/addProduct', function(req, res) {
    if (!req.body.user_pub_id || !req.body.cloudinary_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {

        var current_date = (new Date()).valueOf().toString();
        var random = Math.random().toString();
        var str = crypto.createHash('sha1').update(current_date + random).digest('hex');

        req.body.pub_id = crypto.createHash('sha1').update(current_date + random).digest('hex');
        var product_pub_id = req.body.pub_id;
        var isChatSuccess = true;

        var latitude = req.body.latitude;
        var longitude = req.body.longitude;
        req.body.created_at = current_date;
        req.body.updated_at = current_date;
        var cloudinary_id = req.body.cloudinary_id;
        delete req.body.cloudinary_id;
        // console.log('=============',req.body)
        // return;
        if (req.body.friend_pub_id) {
            var intervals = req.body.interval;
            var intervalDate = moment().add(intervals, 'hours').valueOf();
            //console.log(intervalDate);
            //return;
            req.body.subscription_end_date = intervalDate;


            var friend_pub_id = req.body.friend_pub_id;
            var local_friend_pub_id = friend_pub_id;
            delete req.body.friend_pub_id;
            delete req.body['language'];
            //cm.getSingleOrderBy('subscription_history',"user_pub_id='" + req.body.user_pub_id + "'",function(err,subshistory){
            //var result = JSON.parse(JSON.stringify(subshistory))
            //subs_end_date: '1581159813894'
            /*if(result.length=='0'){
                intervalDate = moment().add(24, 'hours').valueOf(); // allowed for only 24 hours, if user is not subscribed
                req.body.subscription_end_date =intervalDate;
                
            }else{
                endTime = result[0].subs_end_date;
                if(intervalDate >= endTime){
                    req.body.subscription_end_date = endTime;
                    
                }else{
                    
                    req.body.subscription_end_date = intervalDate;
                }
            }*/

            //console.log('khali:=',result.length);
            //return;

            cm.insert('product', req.body, function(err, result) {

                cm.getallDataWhere('product', {
                    product_id: result.insertId
                }, function(err, result) {

                    var requestData = JSON.parse(JSON.stringify(result));
                    var thumbnaill = null;
                    cloudinary_id
                        .reduce(function(promiesRes, value, index) {
                            return promiesRes

                                .then(function(userMediaRes) {

                                    var current_date = (new Date()).valueOf().toString();
                                    snap1 = {
                                        pub_id: crypto.createHash('sha1').update(value).digest('hex'),
                                        product_pub_id: product_pub_id,
                                        media_url: "https://d1z27filp6jkgz.cloudfront.net/",
                                        thumb_url: "https://d1z27filp6jkgz.cloudfront.net/thumbnails/.png",
                                        created_at: current_date,
                                        updated_at: current_date,
                                        cloudinary_id: value
                                    }
                                    return cm.insert('user_media', snap1)
                                })
                                .then(function(userMediaRes) {
                                    return new Promise(function(resolve, reject) {
                                        cm.getallDataWhere('user', {
                                            pub_id: req.body.user_pub_id
                                        }, function(err, userMediaRes) {
                                            if (err) {
                                                //console.log('\n\n -- err: ', err);
                                                reject(err);
                                            }
                                            resolve(userMediaRes);
                                        })
                                    })
                                })
                                .then(function(userMediaRes) {
                                    var userData = JSON.parse(JSON.stringify((userMediaRes[0])));
                                    var edate = (new Date()).valueOf().toString();
                                    delete req.body.pub_id;
                                    req.body.sender_name = userData.name
                                    req.body.date = edate

                                    return nestedDataV1(local_friend_pub_id, edate, req, snap1, latitude, longitude)
                                })
                                .then(function(nestedDataRes) {

                                    return nestedDataRes;
                                })
                                .catch(function(error) {
                                    console.log(' -- error: ', error);
                                    return error.message;
                                })
                        }, Promise.resolve(null));
                });
            });
            if (isChatSuccess) {
                res.send({
                    "status": 1,
                    "message": constant.MSGSUCCESS,
                    "pub_id": product_pub_id
                });
            } else {
                res.send({
                    "status": 0,
                    "message": constant.MSGERR
                });
            }


            //})

        } else {
            delete req.body.friend_pub_id;
            delete req.body['language'];
            var intervals = req.body.interval;
            var intervalDate = moment().add(intervals, 'hours').valueOf();
            //var subsEndDate =moment.unix(intervalDate/1000).format("DD MMM YYYY")
            //console.log(subsEndDate);
            req.body.subscription_end_date = intervalDate;
            //cm.getSingleOrderBy('subscription_history',"user_pub_id='" + req.body.user_pub_id + "'",function(err,subshistory){
            //var result = JSON.parse(JSON.stringify(subshistory))
            //subs_end_date: '1581159813894'
            /*if(result.length=='0'){
                intervalDate = moment().add(24, 'hours').valueOf(); // allowed for only 24 hours, if user is not subscribed
                req.body.subscription_end_date =intervalDate;
                
            }else{
                endTime = result[0].subs_end_date;
                if(intervalDate >= endTime){
                    req.body.subscription_end_date = endTime;
                    
                }else{
                    
                    req.body.subscription_end_date = intervalDate;
                }
            }*/

            cm.insert('product', req.body, function(err, result) {
                //console.log(err);
                cm.getallDataWhere('product', {
                    product_id: result.insertId
                }, function(err, result) {

                    var data = JSON.parse(JSON.stringify(result[0]));
                    cloudinary_id
                        .reduce(function(promiesRes, value, index) {
                            return promiesRes

                                .then(function(result) {
                                    var current_date = (new Date()).valueOf().toString();

                                    snap1 = {
                                        pub_id: crypto.createHash('sha1').update(value).digest('hex'),
                                        product_pub_id: req.body.pub_id,
                                        media_url: "https://d24omluomygbgb.cloudfront.net/",
                                        thumb_url: "https://d24omluomygbgb.cloudfront.net/thumbnails/",
                                        created_at: current_date,
                                        updated_at: current_date,
                                        cloudinary_id: value
                                    }
                                    return cm.insert('user_media', snap1)
                                })
                                .catch(function(error) {
                                    console.log(' -- error: ', error);
                                    return error.message;
                                })
                        }, Promise.resolve(null));

                    var message = res.send({
                        "status": 1,
                        "message": constant.MSGSUCCESS,
                        "pub_id": data.pub_id
                    });
                });
            });
            //})
        }
    }
});

app.post('/rePublishVideo', function(req, res) {
    if (!req.body.product_pub_id || !req.body.interval) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('product', {
            pub_id: req.body.product_pub_id
        }, function(err, productresult) {
            if (productresult.length == 0) {
                res.send({
                    "status": 0,
                    "message": constant.NO_PRODUCT_FOUND
                });
            } else {
                var intervalDate = moment().add(req.body.interval, 'hours').valueOf();

                cm.rePublishProduct(req.body.product_pub_id, req.body.interval, intervalDate, function(err, result) {
                    if (err) {
                        console.log(err);
                        res.send({
                            "status": 0,
                            "message": constant.ERR
                        });
                    } else {

                        res.send({
                            "status": 1,
                            "message": constant.PRODUCT_REPUBLISHED_SUCCESS
                        });
                    }
                });
            }
        });
    }
});

function nestedDataV1(friendId, edate, req, snap1, latitude = '', longitude = '') {
    if (friendId) {
        return friendId
            .reduce(function(friendPromies, friendValue, index) {
                return friendPromies
                    .then(function(friendData) {

                        req.body.media = "https://d1z27filp6jkgz.cloudfront.net/";
                        req.body.thumb = "https://d1z27filp6jkgz.cloudfront.net/thumbnails/.png";
                        req.body.media = snap1.media_url;
                        req.body.thumb = snap1.thumb_url;
                        req.body.user_pub_id_receiver = friendValue;
                        req.body.chat_type = "4";
                        req.body.cloudinary_id = snap1.cloudinary_id;

                        var chat_data = {
                            user_pub_id: req.body.user_pub_id,
                            media_owner_pub_id: req.body.user_pub_id,
                            media_id: snap1.pub_id,
                            media: snap1.media_url,
                            thumb: snap1.thumb_url,
                            user_pub_id_receiver: friendValue,
                            date: edate,
                            chat_type: "4",
                            cloudinary_id: snap1.cloudinary_id,
                            latitude: latitude,
                            longitude: longitude

                        }

                        return new Promise(function(resolve, reject) {
                            cm.insert('chat', chat_data, function(err, chatRes) {
                                if (err) {
                                    console.log('\n\n -- err: ', err);
                                    reject(err);
                                }
                                // console.log(' -- chatRes: ' + JSON.stringify(chatRes));
                                resolve(chatRes);
                            })
                        })
                    })
                    .catch(function(error) {
                        console.log(' -- friend_error: ', error);
                        return error.message;
                    })
            }, Promise.resolve({}));
    } else {

        console.log('Nothing to reduce');
        return '';
    }
}

app.post("/voiceTextSearch", function(req, res) {

    if (!req.body.user_pub_id || !req.body.latitude || !req.body.longitude || !req.body.radius) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        if (req.body.category_pub_id) {
            cm.getallDataWhere('category', {
                pub_id: req.body.category_pub_id
            }, function(err, category) {
                if (category.length == 0) {
                    res.send({
                        status: 0,
                        message: constant.NO_DATA
                    });
                } else {
                    if (req.body.keyword || req.body.search) {
                        if (!req.body.keyword && req.body.search) {
                            var searchArr = [];
                            searchArr = _.split(req.body.search, ",");
                            where = {
                                't.status': 1,
                                //access: 1,
                                category_pub_id: req.body.category_pub_id
                            };
                            my.getSearchData(req.body.latitude, req.body.longitude, 'product', where, searchArr, req.body.user_pub_id, req.body.radius, function(err, productData) {
                                searchResponse(productData, req.body.user_pub_id, req.body.language, function(final_result) {
                                    if (final_result == 0) {
                                        res.send({
                                            "status": 0,
                                            "message": constant.NO_DATA
                                        });
                                    } else {
                                        res.send({
                                            "status": 1,
                                            "message": constant.PRODUCTS,
                                            "data": final_result
                                        });
                                    }
                                });
                            });

                        } else if (req.body.keyword && req.body.search) {
                            var searchData = req.body.keyword + " " + req.body.search;
                            var searchArr = [];

                            // searchArr = searchData.split(" ");
                            searchArr = _.split(searchData, ",");
                            where = {
                                't.status': 1,
                                category_pub_id: req.body.category_pub_id
                            };
                            my.getSearchData(req.body.latitude, req.body.longitude, 'product', where, searchArr, req.body.user_pub_id, 1000000000, function(err, productData) {

                                searchResponse(productData, req.body.user_pub_id, req.body.language, function(final_result) {
                                    if (final_result == 0) {
                                        res.send({
                                            "status": 0,
                                            "message": constant.NO_DATA
                                        });
                                    } else {
                                        res.send({
                                            "status": 1,
                                            "message": constant.PRODUCTS,
                                            "data": final_result
                                        });
                                    }
                                });
                            });

                        } else {
                            var keywordArr = [];
                            keywordArr = _.split(req.body.keyword, " ");
                            where = {
                                't.status': 1,
                                category_pub_id: req.body.category_pub_id
                            };
                            my.getSearchData(req.body.latitude, req.body.longitude, 'product', where, keywordArr, req.body.user_pub_id, 1000000000, function(err, productData) {
                                searchResponse(productData, req.body.user_pub_id, req.body.language, function(final_result) {
                                    if (final_result == 0) {
                                        res.send({
                                            "status": 0,
                                            "message": constant.NO_DATA
                                        });
                                    } else {
                                        res.send({
                                            "status": 1,
                                            "message": constant.PRODUCTS,
                                            "data": final_result
                                        });
                                    }
                                });
                            });
                        }
                    } else {
                        where = {
                            status: 1,
                            category_pub_id: req.body.category_pub_id
                        };
                        my.getSearchDataWithoutTag(req.body.latitude, req.body.longitude, 'product', where, req.body.user_pub_id, 1000000000, function(err, productData) {
                            searchResponse(productData, req.body.user_pub_id, req.body.language, function(final_result) {
                                if (final_result == 0) {
                                    res.send({
                                        "status": 0,
                                        "message": constant.NO_DATA
                                    });
                                } else {
                                    res.send({
                                        "status": 1,
                                        "message": constant.PRODUCTS,
                                        "data": final_result
                                    });
                                }
                            });
                        });
                    }

                }
            });
        } else {
            if (req.body.keyword || req.body.search) {
                if (!req.body.keyword && req.body.search) {
                    var searchArr = [];
                    searchArr = _.split(req.body.search, " ");
                    where = {
                        't.status': 1
                    };
                    my.getSearchData(req.body.latitude, req.body.longitude, 'product', where, searchArr, req.body.user_pub_id, req.body.radius, function(err, productData) {

                        searchResponse(productData, req.body.user_pub_id, req.body.language, function(final_result) {
                            if (final_result == 0) {
                                res.send({
                                    "status": 0,
                                    "message": constant.NO_DATA
                                });
                            } else {
                                res.send({
                                    "status": 1,
                                    "message": constant.PRODUCTS,
                                    "data": final_result
                                });
                            }
                        });
                    });
                } else if (req.body.keyword && req.body.search) {
                    var searchData = req.body.keyword + " " + req.body.search;
                    var searchArr = [];
                    searchArr = _.split(searchData, " ");
                    where = {
                        't.status': 1
                    };
                    my.getSearchData(req.body.latitude, req.body.longitude, 'product', where, searchArr, req.body.user_pub_id, req.body.radius, function(err, productData) {
                        searchResponse(productData, req.body.user_pub_id, req.body.language, function(final_result) {
                            if (final_result == 0) {
                                res.send({
                                    "status": 0,
                                    "message": constant.NO_DATA
                                });
                            } else {
                                res.send({
                                    "status": 1,
                                    "message": constant.PRODUCTS,
                                    "data": final_result
                                });
                            }
                        });
                    });
                } else {
                    var keywordArr = [];
                    keywordArr = _.split(req.body.keyword, " ");
                    where = {
                        't.status': 1
                    };
                    my.getSearchData(req.body.latitude, req.body.longitude, 'product', where, keywordArr, req.body.user_pub_id, req.body.radius, function(err, productData) {

                        searchResponse(productData, req.body.user_pub_id, req.body.language, function(final_result) {
                            if (final_result == 0) {
                                res.send({
                                    "status": 0,
                                    "message": constant.NO_DATA
                                });
                            } else {
                                res.send({
                                    "status": 1,
                                    "message": constant.PRODUCTS,
                                    "data": final_result
                                });
                            }
                        });
                    });
                }
            } else {
                where = {
                    status: 1
                };
                my.getSearchDataWithoutTag(req.body.latitude, req.body.longitude, 'product', where, req.body.user_pub_id, req.body.radius, function(err, productData) {
                    searchResponse(productData, req.body.user_pub_id, req.body.language, function(final_result) {
                        if (final_result == 0) {
                            res.send({
                                "status": 0,
                                "message": constant.NO_DATA
                            });
                        } else {
                            res.send({
                                "status": 1,
                                "message": constant.PRODUCTS,
                                "data": final_result
                            });
                        }
                    });

                });
            }
        }

    }
});


app.post("/searchManualCar", function(req, res) {
    var language = req.headers.language;
    var language = req.body.language;
    if (!req.body.user_pub_id || !req.body.latitude || !req.body.longitude || !req.body.radius) {

        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        if (req.body.start_year) {
            my.getSearchDataWithoutTagBetween(req.body.latitude, req.body.longitude, 'product', req.body.where[0], req.body.user_pub_id, req.body.radius, req.body.start_year, req.body.end_year, function(err, productData) {
                searchResponseCar(productData, req.body.user_pub_id, language, function(final_result) {
                    if (final_result == 0) {
                        res.send({
                            "status": 0,
                            "message": constant.NO_DATA
                        });
                    } else {
                        res.send({
                            "status": 1,
                            "message": constant.PRODUCTS,
                            "data": final_result
                        });
                    }
                });
            });
        } else {
            my.getSearchDataWithoutTag(req.body.latitude, req.body.longitude, 'product', req.body.where[0], req.body.user_pub_id, req.body.radius, function(err, productData) {
                searchResponseCar(productData, req.body.user_pub_id, language, function(final_result) {
                    if (final_result == 0) {
                        res.send({
                            "status": 0,
                            "message": constant.NO_DATA
                        });
                    } else {
                        res.send({
                            "status": 1,
                            "message": constant.PRODUCTS,
                            "data": final_result
                        });
                    }
                });
            });
        }
    }
});


app.post("/searchManualProperties", function(req, res) {
    var language = req.body.language;
    if (!req.body.user_pub_id || !req.body.latitude || !req.body.longitude || !req.body.radius) {
        var language = req.headers.language;
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        if (req.body.start_price) {
            my.getSearchBetweenPrice(req.body.latitude, req.body.longitude, 'product', req.body.where[0], req.body.user_pub_id, req.body.radius, req.body.start_price, req.body.end_price, function(err, productData) {
                searchResponseCar(productData, req.body.user_pub_id, language, function(final_result) {
                    if (final_result == 0) {
                        res.send({
                            "status": 0,
                            "message": constant.NO_DATA
                        });
                    } else {
                        res.send({
                            "status": 1,
                            "message": constant.PRODUCTS,
                            "data": final_result
                        });
                    }
                });
            });
        } else {
            my.getSearchDataWithoutTag(req.body.latitude, req.body.longitude, 'product', req.body.where[0], req.body.user_pub_id, req.body.radius, function(err, productData) {
                searchResponseCar(productData, req.body.user_pub_id, language, function(final_result) {
                    if (final_result == 0) {
                        res.send({
                            "status": 0,
                            "message": constant.NO_DATA
                        });
                    } else {
                        res.send({
                            "status": 1,
                            "message": constant.PRODUCTS,
                            "data": final_result
                        });
                    }
                });
            });
        }
    }
});


app.post("/searchManualFood", function(req, res) {
    var language = req.headers.language;
    var language = req.body.language;
    if (!req.body.user_pub_id || !req.body.latitude || !req.body.longitude || !req.body.radius) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        my.getSearchDataWithoutTag(req.body.latitude, req.body.longitude, 'product', req.body.where[0], req.body.user_pub_id, req.body.radius, function(err, productData) {
            searchResponseCar(productData, req.body.user_pub_id, language, function(final_result) {
                if (final_result == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.NO_DATA
                    });
                } else {
                    res.send({
                        "status": 1,
                        "message": constant.PRODUCTS,
                        "data": final_result
                    });
                }
            });
        });
    }
});
var con = require('./config/connect');
const geolib = require('geolib');
app.post("/searchFoodbykilometer", async function(req, res) {
    //res.send(req.body)

    var language = req.headers.language;
    var language = req.body.language;
    if (!req.body.latitude || !req.body.longitude || !req.body.radius) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        var latitude = req.body.latitude;
        var longitude = req.body.longitude;
        var radius = req.body.radius;

        var food = [];
        var km = [];
        var car = [];
        var realstate = [];
        const mediadata = [];

        //console.log(radius)
        // console.log(geolib.getDistance({'latitude':latitude,'longitude':longitude}, {
        //        latitude: 22.74983760,
        //        longitude: 74.89887070,
        //    }))
        var que = "select * from product where access='1'";
        await con.query(que, async function(err, productData) {
            for (var k of productData) {

                var distence = geolib.getDistance({ 'latitude': latitude, 'longitude': longitude }, {
                    latitude: k.latitude,
                    longitude: k.longitude,
                })

                //console.log(k)
                if (distence <= radius) {

                    switch (k.category_pub_id) {
                        case 'd7887cc9964a5a7a':
                            //if(k.pub_id){

                            var pubid = k.pub_id
                                // res.send(pubid);
                            await con.query("select * from user_media where product_pub_id=? ", pubid, async function(err, mediaresult) {

                                if (err) {
                                    res.send({
                                        'status': 0,
                                        'message': 'somthing wrong'
                                    })
                                } else {
                                    if (mediaresult) {

                                        // mediadata.forEach(
                                        //     mediadata=> k.mediadata=mediadata
                                        //     )

                                        for (var m of mediaresult) {
                                            mediadata.push(m)
                                                //k.mediadata=m;


                                            // console.log(mediadata)
                                        }

                                    } else {
                                        res.send({ 'status': 0, 'message': 'media result not found' })


                                    }

                                }


                            });


                            car.push(k);



                            break;
                        case 'a0d0dd142100d754':
                            food.push(k);
                            //console.log(food);
                            break;
                        case 'fb28949352705e47':
                            realstate.push(k)
                                //console.log(realstate);
                            break;
                        case '41743625e1950eca':
                            km.push(k);
                            // console.log(km);
                            break;

                    }


                }


            }


            var resultarray = {
                'status': 1,
                'message': 'Data fatched successfully.',
                'car': car,
                'food': food,
                'km': km,
                'realstate': realstate
            }
            res.send(resultarray);
        });
        //     my.getSearchAlldata(req.body.latitude, req.body.longitude, 'product', 'where', radius, function(err, productData) {
        //         searchResponseCar(productData, req.body.user_pub_id, language, function(final_result) {
        //             if (final_result == 0) {
        //                 res.send({
        //                     "status": 0,
        //                     "message": constant.NO_DATA
        //                 });
        //             } else {
        //                 res.send({
        //                     "status": 1,
        //                     "message": constant.PRODUCTS,
        //                     "data": final_result
        //                 });
        //             }
        //         });
        // });
    }
});

app.post("/getSimilarProducts", function(req, res) {
    var language = req.headers.language;
    var language = req.body.language;
    //console.log(language);
    if (!req.body.user_pub_id || !req.body.latitude || !req.body.longitude || !req.body.radius) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        my.getSearchDataForSimilar(req.body.latitude, req.body.longitude, 'product', req.body.where[0], req.body.user_pub_id, req.body.radius, function(err, productData) {

            if (productData.length == 0) {
                res.send({
                    "status": 0,
                    "message": constant.NO_DATA
                });
                return;
            }

            if (productData[0].sub_cat_pub_id == "null" || typeof productData[0].sub_cat_pub_id == "undefined") {
                my.getSearchDataWithoutTagSimilar(req.body.latitude, req.body.longitude, 'product', req.body.where[0], req.body.user_pub_id, productData[0].pub_id, req.body.radius, function(err, productData) {
                    searchResponseCar(productData, req.body.user_pub_id, language, function(final_result) {
                        if (final_result == 0) {
                            res.send({
                                "status": 0,
                                "message": constant.NO_DATA
                            });
                        } else {
                            res.send({
                                "status": 1,
                                "message": constant.PRODUCTS,
                                "data": final_result
                            });
                        }
                    });
                });
            } else {
                var new_where = {};
                new_where.sub_cat_pub_id = productData[0].sub_cat_pub_id;
                if (typeof productData[0].car_model_pub_id != "undefined" && productData.car_model_pub_id != "null") {
                    new_where.car_model_pub_id = productData[0].car_model_pub_id;
                }
                if (typeof productData[0].car_brand_pub_id != "undefined" && productData.car_brand_pub_id != "null") {
                    new_where.car_brand_pub_id = productData[0].car_brand_pub_id;
                }


                my.getSearchDataWithoutTagSimilar(req.body.latitude, req.body.longitude, 'product', new_where, req.body.user_pub_id, productData[0].pub_id, req.body.radius, function(err, productData) {
                    searchResponseCar(productData, req.body.user_pub_id, language, function(final_result) {
                        if (final_result == 0) {
                            res.send({
                                "status": 0,
                                "message": constant.NO_DATA
                            });
                        } else {
                            res.send({
                                "status": 1,
                                "message": constant.PRODUCTS,
                                "data": final_result
                            });
                        }
                    });
                });
            }


        });
    }
});

app.post("/getProductByCategory", function(req, res) {
    var language = req.headers.language;
    var language = req.body.language;
    if (!req.body.user_pub_id || !req.body.latitude || !req.body.longitude || !req.body.radius) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        my.getSearchDataWithoutTag(req.body.latitude, req.body.longitude, 'product', req.body.where[0], req.body.user_pub_id, req.body.radius, function(err, productData) {
            searchResponseCar(productData, req.body.user_pub_id, language, function(final_result) {
                if (final_result == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.NO_DATA
                    });
                } else {
                    res.send({
                        "status": 1,
                        "message": constant.PRODUCTS,
                        "data": final_result
                    });
                }
            });
        });
    }
});

app.post("/searchManualKM", function(req, res) {
    var language = req.headers.language;
    var language = req.body.language;
    if (!req.body.user_pub_id || !req.body.latitude || !req.body.longitude || !req.body.radius) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        my.getSearchDataWithoutTag(req.body.latitude, req.body.longitude, 'product', req.body.where[0], req.body.user_pub_id, req.body.radius, function(err, productData) {
            searchResponseCar(productData, req.body.user_pub_id, language, function(final_result) {
                if (final_result == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.NO_DATA
                    });
                } else {
                    res.send({
                        "status": 1,
                        "message": constant.PRODUCTS,
                        "data": final_result
                    });
                }
            });
        });
    }
});

app.post("/getKMLikesProducts", function(req, res) {
    var language = req.headers.language;
    var language = req.body.language;
    if (!req.body.user_pub_id || !req.body.latitude || !req.body.longitude || !req.body.radius) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        where = {
            status: 1
        };
        var likes = 3;
        my.getKMLikesProducts(req.body.latitude, req.body.longitude, 'product', where, req.body.user_pub_id, req.body.radius, likes, function(err, productData) {
            searchResponseCar(productData, req.body.user_pub_id, language, function(final_result) {
                if (final_result == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.NO_DATA
                    });
                } else {
                    // var final_result=JSON.parse(JSON.stringify(final_result));
                    // var product_pub_id=final_result[0].pub_id;    

                    // my.getLikee(req.body.user_pub_id,product_pub_id,function(err,result){
                    //     if(err){
                    //         console.log(err);
                    //     }else{
                    //         var result=JSON.parse(JSON.stringify(result));
                    //         if(result.length>0){
                    //             final_result.isLike=1;
                    //         }else{
                    //             final_result.isLike=0;
                    //         }
                    res.send({
                        "status": 1,
                        "message": constant.PRODUCTS,
                        "data": final_result
                    });
                    //     }
                    // })


                }
            });
        });
    }
});

app.post("/getMyLikedProducts", function(req, res) {
    var language = req.headers.language;
    var language = req.body.language;
    if (!req.body.user_pub_id || !req.body.latitude || !req.body.longitude || !req.body.radius) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {

        cm.getallDataWhere('likes_views', {
            user_pub_id: req.body.user_pub_id,
            type: 1
        }, function(err, like_data) {

            if (like_data.length == 0) {
                res.send({
                    "status": 0,
                    "message": constant.NO_DATA
                });
            } else {

                like_data
                    .reduce(function(promiesRes, liekdata, index) {
                        return promiesRes
                            .then(function(data) {

                                return new Promise(function(resolve, reject) {
                                    var pub_id = liekdata.product_pub_id;
                                    where = {
                                        status: 1,
                                        pub_id: pub_id,
                                    };
                                    var likes = 3;
                                    my.getSearchDataWithoutTag(req.body.latitude, req.body.longitude, 'product', where, req.body.user_pub_id, 100000, function(err, productData) {
                                        searchResponseCar(productData, req.body.user_pub_id, language, function(final_result) {
                                            if (final_result != 0) {
                                                liekdata.product = final_result[0];
                                            }
                                            resolve(liekdata);
                                        });
                                    });
                                });
                            })
                            .catch(function(error) {
                                res.send({
                                    "status": 0,
                                    "message": constant.INTERNAL_ERROR
                                });
                                return error.message;
                            })
                    }, Promise.resolve(null)).then(arrayOfResults => {

                        var like_products = [];
                        for (var i = 0; i < like_data.length; i++) {
                            if (typeof like_data[i].product != "undefined" && like_data[i].product != "undefined") {
                                like_products.push(like_data[i].product);
                            }
                        }

                        res.send({
                            "status": 1,
                            "message": constant.ALL_CAT,
                            "data": like_products
                        });
                    });
            }
        });
    }
});

function searchResponse(productData, user_pub_id, language, cb) {

    if (productData.length > 0) {
        var final_result = [];


        productData
            .reduce(function(promiesRes, product_result, index) {
                return promiesRes
                    .then(function(data) {

                        return new Promise(function(resolve, reject) {
                            cm.getMediaDatails(product_result.pub_id, function(err, user_media) {
                                product_result.media = user_media;
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.getallDataWhere('likes_views', {
                                user_pub_id: user_pub_id,
                                product_pub_id: product_result.pub_id,
                                type: 1
                            }, function(err, like_data) {

                                if (like_data.length == 0) {
                                    product_result.isLike = "0";
                                } else {
                                    product_result.isLike = "1";
                                }
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.getallDataWhere('comments', {
                                product_pub_id: product_result.pub_id
                            }, function(err, comment_result) {
                                product_result.getCommentsCount = comment_result.length;
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.getallDataWhere('likes_views', {
                                product_pub_id: product_result.pub_id,
                                type: 1
                            }, function(err, like_result) {
                                product_result.getLikesCount = like_result.length;
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.getallDataWhere('likes_views', {
                                product_pub_id: product_result.pub_id,
                                type: 2
                            }, function(err, view_result) {
                                product_result.getViewCount = view_result.length;
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.getallDataWhere('forward', {
                                product_pub_id: product_result.pub_id
                            }, function(err, forword_result) {
                                product_result.getForwordCount = forword_result.length;
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {

                            cm.getallDataWhere('user', {
                                pub_id: product_result.user_pub_id
                            }, function(err, user_result) {
                                if (user_result.length > 0) {
                                    product_result.userImage = base_url + user_result[0].profile_image;
                                    product_result.profile_name = user_result[0].name;
                                    product_result.userName = user_result[0].user_name;
                                    product_result.mobile_number = user_result[0].mobile_number;
                                    product_result.country_code = user_result[0].country_code;
                                    product_result.user_mode = user_result[0].user_mode;
                                } else {
                                    product_result.userImage = '';
                                    product_result.userName = '';
                                    product_result.profile_name = '';
                                    product_result.mobile_number = '';
                                    product_result.country_code = '';
                                    product_result.user_mode = '';
                                }
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            if (product_result.category_pub_id != '') {
                                cm.getCategoryById(language, product_result.category_pub_id, function(err, category_result) {
                                    if (category_result.length > 0) {
                                        product_result.category_name = category_result[0].category_name;
                                    } else {
                                        product_result.category_name = '';
                                    }
                                    final_result.push(product_result);
                                    resolve(product_result);
                                });
                            } else {
                                product_result.category_name = '';
                                final_result.push(product_result);
                                resolve(product_result);
                            }
                        })
                    })
            }, Promise.resolve(null)).then(arrayOfResults => { // Do something with all results
                return cb(final_result);
            });
    } else {
        return cb(0);

    }
}


async function searchResponseCar(productData, user_pub_id, language, cb) {
    if (productData.length > 0) {
        var final_result = [];
        await productData
            .reduce(function(promiesRes, product_result, index) {

                return promiesRes
                    .then(function(data) {

                        return new Promise(function(resolve, reject) {
                            cm.getMediaDatails(product_result.pub_id, function(err, user_media) {
                                product_result.media = user_media;
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.getallDataWhere('likes_views', {
                                user_pub_id: user_pub_id,
                                product_pub_id: product_result.pub_id,
                                type: 1,
                            }, function(err, like_data) {

                                if (like_data.length == 0) {
                                    product_result.isLike = "0";
                                } else {
                                    product_result.isLike = "1";
                                }
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.getallDataWhere('comments', {
                                product_pub_id: product_result.pub_id
                            }, function(err, comment_result) {
                                product_result.getCommentsCount = comment_result.length;
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.getallDataWhere('likes_views', {
                                product_pub_id: product_result.pub_id,
                                type: 1
                            }, function(err, like_result) {
                                product_result.getLikesCount = like_result.length;
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.getallDataWhere('likes_views', {
                                product_pub_id: product_result.pub_id,
                                type: 2
                            }, function(err, view_result) {
                                product_result.getViewCount = view_result.length;
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.getallDataWhere('forward', {
                                product_pub_id: product_result.pub_id
                            }, function(err, forword_result) {
                                product_result.getForwordCount = forword_result.length;
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {

                            cm.getallDataWhere('user', {
                                pub_id: product_result.user_pub_id
                            }, function(err, user_result) {
                                if (user_result.length > 0) {
                                    product_result.userImage = base_url + user_result[0].profile_image;
                                    product_result.profile_name = user_result[0].name;
                                    product_result.userName = user_result[0].user_name;
                                    product_result.mobile_number = user_result[0].mobile_number;
                                    product_result.country_code = user_result[0].country_code;
                                    product_result.user_mode = user_result[0].user_mode;
                                } else {
                                    product_result.userImage = '';
                                    product_result.userName = '';
                                    product_result.profile_name = '';
                                    product_result.mobile_number = '';
                                    product_result.country_code = '';
                                    product_result.user_mode = '';
                                }
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {

                            if (product_result.category_pub_id != '') {

                                cm.getCategoryById(language, product_result.category_pub_id, function(err, category_result) {

                                    if (category_result.length > 0) {

                                        product_result.category_name = category_result[0].category_name;
                                    } else {
                                        product_result.category_name = '';
                                    }
                                    resolve(product_result);
                                });
                            } else {
                                product_result.category_name = '';
                                resolve(product_result);
                            }

                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            if (product_result.sub_cat_pub_id != '') {
                                cm.getCategoryById(language, product_result.sub_cat_pub_id, function(err, sub_category_result) {
                                    if (sub_category_result.length > 0) {

                                        product_result.sub_category_name = sub_category_result[0].category_name;
                                    } else {
                                        product_result.sub_category_name = '';
                                    }
                                    resolve(product_result);
                                });
                            } else {
                                product_result.sub_category_name = '';
                                resolve(product_result);
                            }

                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            if (product_result.car_brand_pub_id != '') {
                                cm.getBrandById(language, product_result.car_brand_pub_id, function(err, car_brand) {
                                    if (car_brand.length > 0) {

                                        product_result.brand_name = car_brand[0].brand_name;
                                    } else {
                                        product_result.brand_name = '';
                                    }
                                    resolve(product_result);
                                });
                            } else {
                                product_result.brand_name = '';
                                resolve(product_result);
                            }

                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            if (product_result.car_model_pub_id != '') {
                                cm.getModelById(language, product_result.car_model_pub_id, function(err, car_model) {
                                    if (car_model.length > 0) {

                                        product_result.model_name = car_model[0].model_name;
                                    } else {
                                        product_result.model_name = '';
                                    }
                                    resolve(product_result);
                                });
                            } else {
                                product_result.model_name = '';
                                resolve(product_result);
                            }

                        })
                    }).then(function(product_result) {

                        final_result.push(product_result);
                    })
            }, Promise.resolve(null)).then(arrayOfResults => { // Do something with all results
                //console.log(final_result);
                return cb(final_result);
            });
    } else {
        return cb(0);

    }
}


app.post("/contactSyncing", function(req, res) {
    cm.search('user', req.body.contact, req.body.user_pub_id, function(err, result) {
        if (err) {
            console.log("contactSyncing db error: " + err);

        } else {

            var data = JSON.parse(JSON.stringify(result));
            var contact = [];
            var temp = [];
            for (var i = 0; i < req.body.contact.length; i++) {

                for (var f = 0; f < data.length; f++) {
                    if (req.body.contact[i].mobile == data[f].mobile_number) {
                        var con = {
                            "code": data[f].country_code,
                            "mobile": data[f].mobile_number,
                            "userName": req.body.contact[i].name,
                            "user_pub_id": data[f].pub_id,
                            "profile_image": base_url + data[f].profile_image
                        }
                        contact.push(con)
                            // console.log(con);
                    }
                }
            }
            final_result = _.uniqBy(contact, 'mobile');
            res.send({
                "status": 1,
                "message": constant.CONTACT_SEND_SUCCESS,
                "data": final_result
            });
        }
    })
});

app.post("/addReportVideo", function(req, res) {

    if (!req.body.user_pub_id || !req.body.product_pub_id || !req.body.msg) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {

        var user_data = {

            product_pub_id: req.body.product_pub_id,
            user_pub_id: req.body.user_pub_id,
            msg: req.body.msg
        }
        cm.getallDataWhere('product_report', user_data, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {
                if (result.length == 0) {


                    cm.insert('product_report', {
                        product_pub_id: req.body.product_pub_id,
                        user_pub_id: req.body.user_pub_id,
                        created_at: (new Date()).valueOf().toString(),
                        msg: req.body.msg
                    }, function(err, result) {
                        if (err) {
                            res.send({
                                "status": 0,
                                "message": constant.ERR
                            });
                        } else {
                            cm.getallDataWhere('product_report', {
                                product_pub_id: req.body.product_pub_id
                            }, function(err, result) {
                                if (err) {
                                    res.send({
                                        "status": 0,
                                        "message": constant.ERR
                                    });
                                } else {
                                    if (result.length >= 10) {
                                        cm.updateproduct('product', req.body.product_pub_id, req.body.user_pub_id, {
                                            status: 0
                                        }, function(err, result) {
                                            if (err) {
                                                res.send({
                                                    "status": 0,
                                                    "message": constant.ERR
                                                });
                                            } else {

                                                res.send({
                                                    "status": 1,
                                                    "message": constant.PRODUCT_DEACTIVATED_SUCCESS
                                                });
                                            }
                                        });
                                    }
                                }
                            });
                            res.send({
                                "status": 1,
                                "message": constant.VIDEO_REPORTED_SUCCESS
                            });
                        }
                    });
                } else {
                    res.send({
                        "status": 0,
                        "message": constant.ALREADYADDED
                    });
                }
            }
        });
    }
});

app.post("/addView", function(req, res) {

    if (!req.body.user_pub_id || !req.body.product_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('likes_views', {
            user_pub_id: req.body.user_pub_id,
            product_pub_id: req.body.product_pub_id,
            type: 2,
        }, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {
                if (result.length == 0) {
                    var edate = (new Date()).valueOf().toString();
                    req.body.created_at = edate;
                    req.body.type = 2;
                    delete req.body.language;
                    cm.insert('likes_views', req.body, function(err, result) {
                        if (err) {
                            res.send({
                                "status": 0,
                                "message": constant.err
                            });
                        } else {
                            res.send({
                                "status": 1,
                                "message": constant.VIEWADDEDSUCCESS
                            });
                        }
                    });
                } else {

                    res.json({
                        status: 0,
                        message: constant.ALREADYADDED
                    });
                }
            }
        });
    }
});

// get get view  
app.post("/getView", function(req, res) {

    if (!req.body.product_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getview(req.body.product_pub_id, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {
                if (result.length > 0) {
                    res.send({
                        "status": 1,
                        "message": "View",
                        "data": result
                    });
                } else {
                    res.send({
                        "status": 0,
                        "message": constant.NODATAFOUND
                    });
                }
            }
        });
    }
});


// get get forward  
app.post("/getForward", function(req, res) {

    if (!req.body.product_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getforward(req.body.product_pub_id, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {
                if (result.length > 0) {
                    res.send({
                        "status": 1,
                        "message": constant.FORWORDS,
                        "data": result
                    });
                } else {
                    res.send({
                        "status": 0,
                        "message": constant.NODATAFOUND
                    });
                }

            }
        });
    }
});

// app like of product
app.post("/likeDislikeProduct", function(req, res) {

    if (!req.body.user_pub_id || !req.body.product_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('likes_views', {
            user_pub_id: req.body.user_pub_id,
            product_pub_id: req.body.product_pub_id,
            type: 1,
        }, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": err
                });
            } else {
                if (result.length == 0) {
                    cm.productInfo(req.body.product_pub_id, function(err, result) {
                        if (err) {
                            res.send({
                                "status": 0,
                                "message": err
                            });
                        } else {
                            if (result.length > 0) {

                                cm.getallDataWhere('user', {
                                    pub_id: req.body.user_pub_id
                                }, function(err, userData) {
                                    if (userData.length > 0) {
                                        var msg = userData[0].name + ' ' + constant.MSGLIKE_ON_PRODUCT;
                                        cm.pushnotificationComment(userData[0].name, msg, result[0].device_token, '70006', req.body.product_pub_id);

                                        var notPram = {
                                            user_pub_id: result[0].pub_id,
                                            product_pub_id: req.body.product_pub_id,
                                            title: userData[0].name,
                                            notification_type: '70006',
                                            msg: msg,
                                            created_at: (new Date()).valueOf().toString(),
                                        }
                                        cm.insert('notifications', notPram, function(err, result) {});
                                    } else {
                                        res.send({
                                            "status": 0,
                                            "message": constant.USER_NOT_FOUND
                                        });
                                    }
                                });
                                var edate = (new Date()).valueOf().toString();
                                req.body.created_at = edate;
                                req.body.type = 1;
                                delete req.body.language;
                                cm.insert('likes_views', req.body, function(err, result) {
                                    if (err) {
                                        console.log(err);
                                        res.send({
                                            "status": 0,
                                            "message": constant.MSGERR
                                        });
                                    } else {
                                        res.send({
                                            "status": 1,
                                            "message": constant.MSGSUCCESS
                                        });
                                    }
                                });
                            } else {

                                res.json({
                                    status: 0,
                                    message: constant.NO_PRODUCT_FOUND
                                });
                            }
                        }
                    });
                } else {
                    cm.dislike(req.body.product_pub_id, req.body.user_pub_id, function(err, result) {
                        if (err) {
                            res.send({
                                "status": 0,
                                "message": constant.ERR
                            });
                        } else {

                            if (result.affectedRows == 0) {
                                res.send({
                                    "status": 0,
                                    "message": constant.ALREADYADDED
                                });
                            } else {
                                res.send({
                                    "status": 1,
                                    "message": constant.DISLIKED
                                });
                            }
                        }
                    });
                }
            }
        });
    }
});

// get All likes  
app.post("/getLike", function(req, res) {

    if (!req.body.product_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getlike(req.body.product_pub_id, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {
                if (result.length > 0) {
                    res.send({
                        "status": 1,
                        "message": "likes",
                        "data": result
                    });
                } else {
                    res.send({
                        "status": 0,
                        "message": constant.NODATAFOUND
                    });
                }

            }
        });
    }
});


app.post("/addComment", function(req, res) {
    if (!req.body.user_pub_id || !req.body.product_pub_id || !req.body.content) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.productInfo(req.body.product_pub_id, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": err
                });
            } else {
                if (result.length > 0) {

                    cm.getallDataWhere('user', {
                        pub_id: req.body.user_pub_id
                    }, function(err, userData) {
                        if (userData.length > 0) {
                            var msg = userData[0].name + ' ' + constant.MSGCOMMENTD_ON_PRODUCT;
                            if (result[0].device_token) {
                                cm.pushnotificationComment(userData[0].name, msg, result[0].device_token, '70005', req.body.product_pub_id);
                            }


                            var notPram = {
                                user_pub_id: result[0].pub_id,
                                product_pub_id: req.body.product_pub_id,
                                title: userData[0].name,
                                notification_type: '70005',
                                msg: msg,
                                created_at: (new Date()).valueOf().toString(),
                            }
                            cm.insert('notifications', notPram, function(err, result) {});
                        } else {
                            res.send({
                                "status": 0,
                                "message": constant.USER_NOT_FOUND
                            });
                        }
                    });
                    var edate = (new Date()).valueOf().toString();
                    req.body.created_at = edate;
                    delete req.body.language;
                    cm.insert('comments', req.body, function(err, result) {
                        if (err) {

                            res.send({
                                "status": 0,
                                "message": constant.MSGERR
                            });
                        } else {
                            res.send({
                                "status": 1,
                                "message": constant.MSGSUCCESS
                            });
                        }
                    });
                } else {

                    res.json({
                        status: 0,
                        message: constant.NO_PRODUCT_FOUND
                    });
                }
            }
        });
    }
});


app.post("/replyOnComment", function(req, res) {
    if (!req.body.user_pub_id || !req.body.product_pub_id || !req.body.content || !req.body.comment_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.productInfo(req.body.product_pub_id, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": err
                });
            } else {
                if (result.length > 0) {

                    cm.getallDataWhere('user', {
                        pub_id: req.body.user_pub_id
                    }, function(err, userData) {
                        if (userData.length > 0) {
                            var msg = userData[0].name + ' ' + constant.MSGCOMMENTD_ON_PRODUCT;
                            if (result[0].device_token) {
                                cm.pushnotificationComment(userData[0].name, msg, result[0].device_token, '70005', req.body.product_pub_id);
                            }


                            /*var notPram = {
                                user_pub_id: result[0].pub_id,
                                product_pub_id: req.body.product_pub_id,
                                title: userData[0].name,
                                notification_type: '70005',
                                msg: msg,
                                created_at: (new Date()).valueOf().toString(),
                            }
                            cm.insert('notifications', notPram, function(err, result) {});*/
                        } else {
                            res.send({
                                "status": 0,
                                "message": constant.USER_NOT_FOUND
                            });
                        }
                    });
                    var edate = (new Date()).valueOf().toString();
                    req.body.created_at = edate;
                    delete req.body.language;
                    req.body.parent_id = req.body.comment_id;
                    delete req.body.comment_id;
                    cm.insert('comments', req.body, function(err, result) {
                        console.log(err);
                        if (err) {
                            res.send({
                                "status": 0,
                                "message": constant.MSGERR
                            });
                        } else {
                            res.send({
                                "status": 1,
                                "message": constant.MSGSUCCESS
                            });
                        }
                    });
                } else {

                    res.json({
                        status: 0,
                        message: constant.NO_PRODUCT_FOUND
                    });
                }
            }
        });
    }
});

//  get All Comments  
app.post("/getComments", function(req, res) {
    cm.getcomment(req.body.product_pub_id, function(err, get_comments) {

        if (err) {
            res.send({
                "status": 0,
                "message": constant.ERR
            });
        } else {
            get_comments
                .reduce(function(promiesRes, commentData, index) {
                    return promiesRes
                        .then(function(data) {
                            return new Promise(function(resolve, reject) {
                                var comment_id = commentData.comment_id;
                                cm.getcommentReply(req.body.product_pub_id, comment_id, function(err, result1) {
                                    console.log(err);
                                    if (result1.length > 0) {
                                        commentData.comment_reply = result1;
                                    } else {
                                        commentData.comment_reply = Array();
                                    }
                                    resolve(commentData);
                                });
                            });
                        })
                        .catch(function(error) {
                            res.send({
                                "status": 0,
                                "message": constant.INTERNAL_ERROR
                            });
                            return error.message;
                        })
                }, Promise.resolve(null)).then(arrayOfResults => {

                    res.send({
                        "status": 1,
                        "message": constant.COMMENTS,
                        "data": get_comments
                    });
                });
        }
    });
});
// delete comment 
app.post("/deleteComment", function(req, res) {

    if (!req.body.commentID) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.deleteComment(req.body.commentID, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {

                if (result.affectedRows == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.ERR
                    });
                } else {
                    res.send({
                        "status": 1,
                        "message": constant.COMMENT_DELETED
                    });
                }
            }
        });
    }
});

// deactive product 
app.post("/deactiveProduct", function(req, res) {

    if (!req.body.user_pub_id || !req.body.product_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.deactiveProduct(req.body.product_pub_id, req.body.user_pub_id, function(err, result) {
            //res.send(result)
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {
                res.send({
                    "status": 1,
                    "message": constant.PRODUCT_DEACTIVATED_SUCCESS
                });
            }
        });
    }
});

// deactive product 
app.post("/accessUpdateOfProduct", function(req, res) {

    if (!req.body.user_pub_id || !req.body.product_pub_id || !req.body.access) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.updateProductAccess('product', req.body.product_pub_id, req.body.user_pub_id, req.body.access, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {

                if (result.affectedRows == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.ERR
                    });
                } else {
                    res.send({
                        "status": 1,
                        "message": constant.PRODUCT_ACCESS_SUCCESS
                    });
                }

            }
        });
    }
});

// deactive product 
app.post("/soldProduct", function(req, res) {

    if (!req.body.user_pub_id || !req.body.product_pub_id || !req.body.is_sold) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.updateProductSold('product', req.body.product_pub_id, req.body.user_pub_id, req.body.is_sold, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {

                if (result.affectedRows == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.ERR
                    });
                } else {
                    res.send({
                        "status": 1,
                        "message": constant.PRODUCT_SOLD_SUCCESS
                    });
                }
            }
        });
    }
});
// add report video
app.post("/addReportVideo", function(req, res) {

    if (!req.body.user_pub_id || !req.body.product_pub_id || !req.body.msg) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        var user_data = {
            product_pub_id: req.body.product_pub_id,
            user_pub_id: req.body.user_pub_id,
            msg: req.body.msg
        }
        cm.getallDataWhere('product_report', user_data, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {
                if (result.length == 0) {
                    cm.insert('product_report', {
                        product_pub_id: req.body.product_pub_id,
                        user_pub_id: req.body.user_pub_id,
                        created_at: (new Date()).valueOf().toString(),
                        msg: req.body.msg
                    }, function(err, result) {
                        if (err) {
                            res.send({
                                "status": 0,
                                "message": constant.ERR
                            });
                        } else {
                            cm.getallDataWhere('product_report', {
                                product_pub_id: req.body.product_pub_id
                            }, function(err, result) {
                                if (err) {
                                    res.send({
                                        "status": 0,
                                        "message": constant.ERR
                                    });
                                } else {
                                    if (result.length >= 10) {
                                        cm.updateproduct('product', req.body.product_pub_id, req.body.user_pub_id, {
                                            status: 0
                                        }, function(err, result) {
                                            if (err) {
                                                res.send({
                                                    "status": 0,
                                                    "message": constant.ERR
                                                });
                                            } else {

                                                res.send({
                                                    "status": 1,
                                                    "message": constant.PRODUCT_DEACTIVATED_SUCCESS
                                                });
                                            }
                                        });
                                    }
                                }
                            });
                            res.send({
                                "status": 1,
                                "message": constant.VIDEO_REPORTED_SUCCESS
                            });
                        }
                    });
                } else {
                    res.send({
                        "status": 0,
                        "message": constant.ALREADYADDED
                    });
                }
            }
        });
    }
});

app.post("/blockList", function(req, res) {

    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getBlockList(req.body.user_pub_id, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {
                if (result.length > 0) {
                    res.send({
                        "status": 1,
                        "message": constant.BLOCKLIST,
                        "blockList": result
                    });
                } else {
                    res.send({
                        "status": 0,
                        "message": constant.NODATAFOUND
                    });
                }
            }
        });
    }
});

app.post("/blockUnblock", function(req, res) {

    if (!req.body.user_pub_id || !req.body.block_user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('block_list', {
            user_pub_id: req.body.user_pub_id,
            block_user_pub_id: req.body.block_user_pub_id
        }, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {
                if (result.length == 0) {
                    cm.getallDataWhere('user', {
                        pub_id: req.body.block_user_pub_id
                    }, function(err, userdata) {
                        if (userdata.length > 0) {
                            var edate = (new Date()).valueOf().toString();
                            req.body.created_at = edate;
                            delete req.body.language;
                            cm.insert('block_list', req.body, function(err, result) {
                                if (err) {
                                    res.send({
                                        "status": 0,
                                        "message": err
                                    });
                                } else {
                                    res.send({
                                        "status": 1,
                                        "message": userdata[0].name + ' ' + constant.MSGBLOCK
                                    });
                                }
                            });
                        } else {
                            res.send({
                                "status": 0,
                                "message": constant.USER_NOT_FOUND
                            });
                        }
                    });
                } else {
                    cm.unblock(req.body.block_user_pub_id, req.body.user_pub_id, function(err, result) {
                        if (err) {
                            res.send({
                                "status": 0,
                                "message": constant.ERR
                            });
                        } else {
                            if (result.affectedRows == 0) {
                                res.send({
                                    "status": 0,
                                    "message": constant.ERR
                                });
                            } else {
                                res.send({
                                    "status": 1,
                                    "message": constant.MSGUNBLOCK
                                });
                            }
                        }
                    });
                }
            }
        });
    }
});


app.post("/followUnfollowUser", function(req, res) {
    if (!req.body.user_pub_id || !req.body.following_user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('user', {
            pub_id: req.body.user_pub_id
        }, function(err, userdata) {
            if (userdata.length == 0) {
                res.send({
                    "status": 0,
                    "message": constant.USER_NOT_FOUND
                });
            } else {
                cm.getallDataWhere('user', {
                    pub_id: req.body.following_user_pub_id
                }, function(err, followinguserdata) {
                    if (followinguserdata.length == 0) {
                        res.send({
                            "status": 0,
                            "message": constant.USER_NOT_FOUND
                        });
                    } else {
                        cm.getallDataWhere('followers', {
                            following_user_pub_id: req.body.following_user_pub_id,
                            user_pub_id: req.body.user_pub_id
                        }, function(err, result) {
                            if (result.length == 0) {
                                delete req.body.language;
                                cm.insert('followers', req.body, function(err, addfollow) {
                                    res.send({
                                        "status": 1,
                                        "message": constant.FOLLOW_SUCCESS
                                    });
                                });
                            } else {

                                cm.unFollow(req.body.user_pub_id, req.body.following_user_pub_id, function(err, fdelete) {
                                    res.send({
                                        "status": 1,
                                        "message": constant.UNFOLLOW_SUCCESS
                                    });
                                });
                            }
                        });
                    }
                });
            }
        });
    }
});


app.post("/addFeeback", function(req, res) {

    if (!req.body.user_pub_id || !req.body.message) {
        res.json({
            status: 0,
            message: "please check all the fields."
        });
        return;
    } else {

        req.body.created_at = (new Date()).valueOf().toString();
        delete req.body.language;
        cm.insert('feedback', req.body, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": "Error in feedback insert"
                });
            } else {
                my.sendmail(constant.ADMIN_EMAIL, 'Feedback', req.body.message);
                res.send({
                    "status": 1,
                    "message": "feedback added Successfully."
                });
            }
        });
    }
});

app.post("/sendComplaint", function(req, res) {

    if (!req.body.user_pub_id || !req.body.friend_pub_id || !req.body.message) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        req.body.created_at = (new Date()).valueOf().toString();
        delete req.body.language;
        cm.insert('complaint', req.body, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {
                my.sendmail(constant.ADMIN_EMAIL, 'Complaint', req.body.message);
                res.send({
                    "status": 1,
                    "message": constant.COMPLAINT_ADDED
                });
            }
        });
    }
});

app.post("/deleteUser", function(req, res) {

    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.deleteBlockListByUserPubId(req.body.user_pub_id, function(err, result) {});
        cm.deleteChatbyUserPubId(req.body.user_pub_id, function(err, result) {});
        cm.deleteCommentbyUserPubId(req.body.user_pub_id, function(err, result) {});
        cm.deleteFollowersByUserPubId(req.body.user_pub_id, function(err, result) {});
        cm.deleteForwardByUserPubId(req.body.user_pub_id, function(err, result) {});
        cm.deleteFeedbackByUserPubId(req.body.user_pub_id, function(err, result) {});
        cm.deleteLikebyUserPubId(req.body.user_pub_id, function(err, result) {});
        cm.deleteNotificationbyUserPubId(req.body.user_pub_id, function(err, result) {});
        cm.deleteProductReportbyUserPubId(req.body.user_pub_id, function(err, result) {});
        //cm.deleteProductPurchasebyUserPubId(req.body.user_pub_id, function(err, result) {});
        cm.deleteUserbyUserPubId(req.body.user_pub_id, function(err, result) {});

        cm.deleteComplaintbyUserPubId(req.body.user_pub_id, function(err, result) {});
        deleteProduct(req.body.user_pub_id, function(result) {
            res.json({
                status: 1,
                message: constant.USER_DELETED
            });
        });
    }
});

function deleteProduct(user_pub_id, cb) {
    var final_result = [];

    cm.getallDataWhere('product', {
        user_pub_id: user_pub_id
    }, function(err, productData) {
        productData
            .reduce(function(promiesRes, product_result, index) {
                return promiesRes
                    .then(function(data) {

                        return new Promise(function(resolve, reject) {
                            cm.deleteCommentsbyProductPubId(product_result.pub_id, function(err, product) {
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.deleteForwardbyProductPubId(product_result.pub_id, function(err, product) {
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.deleteLikesbyProductPubId(product_result.pub_id, function(err, product) {
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.deleteProductsbyProductPubId(product_result.pub_id, function(err, product) {
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.deleteProductPurchasebyProductPubId(product_result.pub_id, function(err, product) {
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.deleteProductReportbyProductPubId(product_result.pub_id, function(err, product) {
                                resolve(product_result);
                            });
                        })
                    })
                    .then(function(product_result) {

                        return new Promise(function(resolve, reject) {
                            cm.deleteUserMediabyProductPubId(product_result.pub_id, function(err, product) {
                                resolve(product_result);
                            });
                        })
                    })

                .then(function(product_result) {
                    return new Promise(function(resolve, reject) {
                        cm.deleteViewbyProductPubId(product_result.pub_id, function(err, product) {
                            resolve(product_result);
                        });
                    })
                })
            }, Promise.resolve(null)).then(arrayOfResults => { // Do something with all results
                return cb(true);
            });
    });
}

app.post("/deleteChat", function(req, res) {
    if (!req.body.user_pub_id || !req.body.friend_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.deleteChat(req.body.user_pub_id, req.body.friend_pub_id, function(err, result) {
            res.send({
                "status": 1,
                "message": "Chat deleted",
            });
        })
    }
});

app.post("/shareSnap", function(req, res) {
    var username;

    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {

        cm.getallDataWhere('user', {
            pub_id: req.body.user_pub_id
        }, function(err, userresult) {
            if (userresult.length == 0) {
                res.send({
                    "status": 0,
                    "message": constant.USER_NOT_FOUND
                });
            } else {
                cm.getallDataWhere('product', {
                    pub_id: req.body.product_pub_id
                }, function(err, productresult) {
                    if (productresult.length == 0) {
                        res.send({
                            "status": 0,
                            "message": constant.NO_PRODUCT_FOUND
                        });
                    } else {
                        if (req.body.access) {

                            cm.update('product', {
                                pub_id: req.body.product_pub_id
                            }, {
                                access: req.body.access,
                                updated_at: (new Date()).valueOf().toString()
                            }, function(err, updateresult) {
                                console.log('access updated');
                            });
                        }
                        if (typeof req.body.send_to == "undefined" || req.body.send_to.length == 0) {
                            res.send({
                                "status": 1,
                                "message": constant.SHRD_SUCESS
                            });
                        } else {
                            req.body.send_to.forEach(function(data) {
                                cm.getallDataWhere('user', {
                                    pub_id: data.user_pub_id
                                }, function(err, chkuser) {
                                    if (chkuser.length > 0) {
                                        cm.getallDataWhere('user_media', {
                                            product_pub_id: productresult[0].pub_id
                                        }, function(err, user_media_result) {
                                            var i = 1;
                                            var username = userresult[0].name;
                                            user_media_result
                                                .reduce(function(promiesRes, mediadata, index) {
                                                    return promiesRes

                                                        .then(function(data) {

                                                            return new Promise(function(resolve, reject) {
                                                                var dataset = {
                                                                    user_pub_id: req.body.user_pub_id,
                                                                    user_pub_id_receiver: chkuser[0].pub_id,
                                                                    sender_name: username,
                                                                    chat_type: 4,
                                                                    media: mediadata.media_url,
                                                                    media_id: mediadata.pub_id,
                                                                    media_owner_pub_id: productresult[0].user_pub_id,
                                                                    thumb: mediadata.thumb_url,
                                                                    cloudinary_id: mediadata.cloudinary_id,
                                                                    date: (new Date()).valueOf().toString()
                                                                };

                                                                cm.getallDataWhere('user', {
                                                                    pub_id: chkuser[0].pub_id
                                                                }, function(err, result) {
                                                                    if (err) {

                                                                    } else {
                                                                        if (result.length > 0) {

                                                                            cm.getallDataWhere('user', {
                                                                                pub_id: req.body.user_pub_id
                                                                            }, function(err, userData) {
                                                                                if (userData.length > 0) {
                                                                                    var msg = userData[0].name + ' ' + constant.FORWORD_VIDEO;
                                                                                    if (result[0].device_token) {
                                                                                        cm.pushnotificationComment(userData[0].name, msg, result[0].device_token, '70005', req.body.product_pub_id);
                                                                                    }


                                                                                    var notPram = {
                                                                                        user_pub_id: result[0].pub_id,
                                                                                        product_pub_id: req.body.product_pub_id,
                                                                                        title: userData[0].name,
                                                                                        notification_type: '70005',
                                                                                        msg: msg,
                                                                                        created_at: (new Date()).valueOf().toString(),
                                                                                    }
                                                                                    delete req.body.language;
                                                                                    cm.insert('notifications', notPram, function(err, result) {});
                                                                                }
                                                                            });
                                                                        }
                                                                    }
                                                                });
                                                                delete req.body.language;
                                                                cm.insert('chat', dataset, function(err, chatinsert) {
                                                                    resolve(mediadata);
                                                                });
                                                            })
                                                        })
                                                        .then(function(mediadata) {

                                                            return new Promise(function(resolve, reject) {
                                                                var forworddata = {
                                                                    forword_by_pub_id: req.body.user_pub_id,
                                                                    forword_to_pub_id: chkuser[0].pub_id,
                                                                    product_pub_id: req.body.product_pub_id,
                                                                    created_at: (new Date()).valueOf().toString()
                                                                };
                                                                delete req.body.language;
                                                                cm.insert('forward', forworddata, function(err, chatinsert) {
                                                                    resolve(mediadata);
                                                                });
                                                            })
                                                        })


                                                    .catch(function(error) {
                                                        console.log(' -- error: ', error);
                                                        res.send({
                                                            "status": 0,
                                                            "message": constant.ERR
                                                        });
                                                        return error.message;
                                                    })
                                                }, Promise.resolve(null)).then(arrayOfResults => { // Do something with all results

                                                    res.send({
                                                        "status": 1,
                                                        "message": constant.SHRD_SUCESS
                                                    });

                                                });
                                        });
                                    }
                                });
                            });
                        }
                    }
                });
            }
        });
    }
});

app.post("/addRating", function(req, res) {
    if (!req.body.user_pub_id || !req.body.user_pub_id_to_rate || !req.body.rating || !req.body.comment) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('rating', {
            user_pub_id: req.body.user_pub_id,
            user_pub_id_to_rate: req.body.user_pub_id_to_rate
        }, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {
                if (result.length == 0) {
                    var edate = (new Date()).valueOf().toString();
                    req.body.created_at = edate;
                    delete req.body.language;
                    cm.insert('rating', req.body, function(err, result) {
                        if (err) {
                            res.send({
                                "status": 0,
                                "message": constant.err
                            });
                        } else {
                            res.send({
                                "status": 1,
                                "message": constant.VIEWADDEDSUCCESS
                            });
                        }
                    });
                } else {

                    res.json({
                        status: 0,
                        message: constant.ALREADYADDED
                    });
                }
            }
        });
    }
});

app.post("/getMyRating", function(req, res) {

    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getMyRating(req.body.user_pub_id, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.NODATAFOUND
                });
            } else {
                if (result.length > 0) {
                    res.send({
                        "status": 1,
                        "message": constant.COMMENTS,
                        "getComments": result
                    });
                } else {
                    res.send({
                        "status": 0,
                        "message": constant.NODATAFOUND
                    });
                }
            }
        });
    }
});

app.post("/getNotifications", function(req, res) {
    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getNotificationsV1(req.body.user_pub_id, function(err, result) {
            if (result.length > 0) {
                res.send({
                    "status": 1,
                    "message": constant.NOTIFICATIONS,
                    "my_notifications": result
                });
            } else {
                res.send({
                    "status": 0,
                    "message": constant.NO_DATA
                });
            }
        });
    }
});

app.post("/editProduct", function(req, res) {
    if (!req.body.user_pub_id || !req.body.product_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('user', {
            pub_id: req.body.user_pub_id
        }, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {

                if (result.length == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.USER_NOT_FOUND
                    });
                } else {
                    cm.getallDataWhere('product', {
                        pub_id: req.body.product_pub_id
                    }, function(err, result) {
                        if (err) {
                            res.send({
                                "status": 0,
                                "message": constant.ERR
                            });
                        } else {

                            if (result.length == 0) {
                                res.send({
                                    "status": 0,
                                    "message": constant.NO_PRODUCT_FOUND
                                });
                            } else {
                                var product_pub_id = req.body.product_pub_id;
                                delete req.body.product_pub_id;
                                cm.update('product', {
                                    pub_id: product_pub_id
                                }, req.body, function(err, result) {
                                    if (err) {
                                        console.log(err);
                                        res.send({
                                            "status": 0,
                                            "message": constant.ERR + '---' + err
                                        });
                                    } else {
                                        cm.getallDataWhere('product', {
                                            pub_id: product_pub_id
                                        }, function(err, result) {
                                            if (err) {
                                                res.send({
                                                    "status": 0,
                                                    "message": constant.ERR
                                                });
                                            } else {
                                                res.send({
                                                    "status": 1,
                                                    "message": constant.PRO_EDIT,
                                                    "data": result[0]
                                                });
                                            }
                                        });
                                    }
                                });
                            }
                        }
                    });
                }
            }
        });
    }
});

app.post("/sendOffer", function(req, res) {
    if (!req.body.wantToCall) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('user', {
            pub_id: req.body.wantToCall
        }, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {

                if (result.length == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.USER_NOT_FOUND
                    });
                } else {
                    var type = '70003';
                    var element = {};
                    element.data = JSON.stringify(req.body);
                    element.type = JSON.stringify(req.body.callType);

                    cm.pushnotificationV2(result[0].name, 'video call', result[0].device_token, element, type);
                    res.send({
                        "status": 1,
                        "message": "Send Successfully."
                    });
                }
            }
        });
    }
});

app.post("/getFollowingUsers", function(req, res) {
    if (!req.body.user_pub_id || !req.body.friend_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('followers', {
            user_pub_id: req.body.user_pub_id
        }, function(err, followers) {
            if (followers.length == 0) {
                res.send({
                    "status": 0,
                    "message": constant.NODATAFOUND
                });
            } else {
                var final_result = [];
                if (followers.length > 0) {


                    followers
                        .reduce(function(promiesRes, followers_data, index) {
                            return promiesRes
                                .then(function(data) {

                                    return new Promise(function(resolve, reject) {
                                        cm.getallDataWhere('user', {
                                            pub_id: followers_data.following_user_pub_id,
                                            status: 1
                                        }, function(err, result_userdata) {
                                            if (err) {
                                                console.log('\n\n -- err: ', err);
                                                res.send({
                                                    "status": 0,
                                                    "message": constant.INTERNAL_ERROR
                                                });
                                                reject(err);
                                            }
                                            resolve(result_userdata);
                                        })
                                    })
                                })
                                .then(function(result_userdata) {


                                    return new Promise(function(resolve, reject) {

                                        if (result_userdata.length != 0) {
                                            cm.getallDataWhere('followers', {
                                                following_user_pub_id: req.body.friend_pub_id,
                                                user_pub_id: result_userdata[0].pub_id
                                            }, function(err, result_followerdata) {
                                                if (err) {
                                                    console.log('\n\n -- err: ', err);
                                                    res.send({
                                                        "status": 0,
                                                        "message": constant.INTERNAL_ERROR
                                                    });
                                                    reject(err);
                                                }

                                                if (result_followerdata.length > 0) {
                                                    result_userdata[0].is_following = '1';
                                                } else {
                                                    result_userdata[0].is_following = '0';
                                                }

                                                resolve(result_userdata);
                                            })
                                        } else {
                                            resolve(result_userdata);

                                        }
                                    })
                                })
                                .then(function(result_userdata) {


                                    return new Promise(function(resolve, reject) {
                                        if (result_userdata.length != 0) {
                                            cm.getallDataWhere('followers', {
                                                following_user_pub_id: result_userdata[0].pub_id,
                                                user_pub_id: req.body.friend_pub_id
                                            }, function(err, result_followerdata2) {
                                                if (err) {
                                                    console.log('\n\n -- err: ', err);
                                                    res.send({
                                                        "status": 0,
                                                        "message": constant.INTERNAL_ERROR
                                                    });
                                                    reject(err);
                                                }
                                                if (result_followerdata2.length > 0) {
                                                    result_userdata[0].is_follower = '1';
                                                } else {
                                                    result_userdata[0].is_follower = '0';
                                                }
                                                result_userdata[0].profile_image = base_url + result_userdata[0].profile_image;
                                                final_result.push(result_userdata[0]);
                                                resolve(result_userdata);
                                            })
                                        } else {
                                            resolve(result_userdata);
                                        }
                                    })

                                })

                            .catch(function(error) {
                                console.log(' -- error: ', error);
                                res.send({
                                    "status": 0,
                                    "message": constant.INTERNAL_ERROR
                                });
                                return error.message;
                            })
                        }, Promise.resolve(null)).then(arrayOfResults => { // Do something with all results

                            res.send({
                                "status": 1,
                                "message": constant.MY_FOLLOWER,
                                "followers": final_result
                            });

                        });


                } else {
                    res.send({
                        "status": 0,
                        "message": constant.NO_DATA
                    });
                }
            }
        });

    }
});
app.post("/getMyFollowers", function(req, res) {
    if (!req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('user', {
            pub_id: req.body.user_pub_id,
            status: 1
        }, function(err, user) {
            if (user.length == 0) {
                res.send({
                    "status": 0,
                    "message": constant.NODATAFOUND
                });
            } else {
                cm.getallDataWhere('followers', {
                    following_user_pub_id: req.body.user_pub_id
                }, function(err, followers) {
                    if (followers.length > 0) {
                        final_result = [];
                        followers.reduce(function(promiesRes, follower_result, index) {
                            return promiesRes.then(function(data) {
                                return new Promise(function(resolve, reject) {
                                    cm.getallDataWhere('user', {
                                        pub_id: follower_result.user_pub_id,
                                        status: 1
                                    }, function(err, chkUser) {
                                        if (chkUser.length > 0) {
                                            cm.getallDataWhere('followers', {
                                                user_pub_id: chkUser[0].pub_id,
                                                following_user_pub_id: req.body.user_pub_id
                                            }, function(err, follow) {
                                                if (follow.length > 0) {
                                                    chkUser[0].is_following = '1';
                                                } else {
                                                    chkUser[0].is_following = '0';
                                                }
                                                cm.getallDataWhere('followers', {
                                                    user_pub_id: req.body.user_pub_id,
                                                    following_user_pub_id: chkUser[0].pub_id
                                                }, function(err, follow1) {
                                                    if (follow1.length > 0) {
                                                        chkUser[0].is_follower = '1';
                                                    } else {
                                                        chkUser[0].is_follower = '0';
                                                    }
                                                    chkUser[0].profile_image = base_url + chkUser[0].profile_image;
                                                    final_result.push(chkUser[0]);
                                                    resolve(follower_result);

                                                });
                                            });
                                        }
                                    });
                                })
                            })
                        }, Promise.resolve(null)).then(arrayOfResults => { // Do something with all results
                            res.send({
                                "status": 1,
                                "message": constant.MY_FOLLOWER,
                                "followers": final_result
                            });
                        });
                    } else {
                        res.send({
                            "status": 0,
                            "message": constant.NODATAFOUND
                        });
                    }
                });
            }
        });
    }
});
app.post("/myFollowers", function(req, res) {
    if (!req.body.user_pub_id || !req.body.friend_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('user', {
            pub_id: req.body.user_pub_id,
            status: 1
        }, function(err, user) {
            if (user.length == 0) {
                res.send({
                    "status": 0,
                    "message": constant.NODATAFOUND
                });
            } else {
                cm.getallDataWhere('followers', {
                    following_user_pub_id: req.body.user_pub_id
                }, function(err, followers) {
                    if (followers.length > 0) {
                        final_result = [];


                        followers
                            .reduce(function(promiesRes, follower_result, index) {
                                return promiesRes
                                    .then(function(data) {

                                        return new Promise(function(resolve, reject) {
                                            cm.getallDataWhere('user', {
                                                pub_id: follower_result.user_pub_id,
                                                status: 1
                                            }, function(err, chkUser) {
                                                if (chkUser.length > 0) {
                                                    cm.getallDataWhere('followers', {
                                                        user_pub_id: chkUser[0].pub_id,
                                                        following_user_pub_id: req.body.friend_pub_id
                                                    }, function(err, follow) {
                                                        if (follow.length > 0) {
                                                            chkUser[0].is_following = '1';
                                                        } else {
                                                            chkUser[0].is_following = '0';
                                                        }
                                                        cm.getallDataWhere('followers', {
                                                            user_pub_id: req.body.friend_pub_id,
                                                            following_user_pub_id: chkUser[0].pub_id
                                                        }, function(err, follow1) {
                                                            if (follow1.length > 0) {
                                                                chkUser[0].is_follower = '1';
                                                            } else {
                                                                chkUser[0].is_follower = '0';
                                                            }
                                                            chkUser[0].profile_image = base_url + chkUser[0].profile_image;
                                                            final_result.push(chkUser[0]);
                                                            resolve(follower_result);

                                                        });
                                                    });
                                                }
                                            });
                                        })
                                    })
                            }, Promise.resolve(null)).then(arrayOfResults => { // Do something with all results
                                res.send({
                                    "status": 1,
                                    "message": constant.MY_FOLLOWER,
                                    "followers": final_result
                                });
                            });
                    } else {
                        res.send({
                            "status": 0,
                            "message": constant.NODATAFOUND
                        });
                    }
                });
            }
        });
    }
});

app.post("/checkUserStatus", function(req, res) {
    if (!req.body.user_pub_id || !req.body.friend_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        var user_pub_id = req.body.user_pub_id;
        var block_user_pub_id = req.body.friend_pub_id;
        db.query("SELECT * FROM `followers` WHERE (`user_pub_id` = '" + user_pub_id + "' AND `following_user_pub_id` = '" + block_user_pub_id + "' ) ", function(err, followResult) {
            db.query("SELECT * FROM `block_list` WHERE (`user_pub_id` = '" + user_pub_id + "' AND `block_user_pub_id` = '" + block_user_pub_id + "' ) ", function(err, result) {

                if (result.length > 0) {
                    isBlock = "1";
                } else {
                    isBlock = "0";
                }
                if (followResult.length > 0) {
                    isFollow = "1";
                } else {
                    isFollow = "0";
                }

                res.json({
                    status: 1,
                    message: "Get user",
                    isBlock: isBlock,
                    isFollow: isFollow
                });
            });
        });
    }
});


app.post("/rejectCall", function(req, res) {
    if (!req.body.friend_pub_id || !req.body.user_pub_id) {
        res.json({
            status: 0,
            message: constant.CHKAllFIELD
        });
        return;
    } else {
        cm.getallDataWhere('user', {
            pub_id: req.body.friend_pub_id
        }, function(err, result) {
            if (err) {
                res.send({
                    "status": 0,
                    "message": constant.ERR
                });
            } else {

                if (result.length == 0) {
                    res.send({
                        "status": 0,
                        "message": constant.USER_NOT_FOUND
                    });
                } else {
                    var type = '70013';
                    cm.pushnotification(result[0].name, 'Call rejected', result[0].device_token, type);
                    res.send({
                        "status": 1,
                        "message": "Send Successfully."
                    });
                }
            }
        });
    }
});


//=================subscription api start=================
//http://13.232.102.101/admin/uploadedimage/ad_banner-1579702123904.png

var moment = require('moment');
app.get('/getAllPackages', (req, res) => {
    var language = req.headers.language;
    var language = req.body.language;

    db.query('SELECT p.package_id,pd.package_title,pd.package_discription,p.package_image,p.package_amount,p.package_days,p.package_created_at,p.package_updated_at,p.package_status,p.currency_code FROM package as p JOIN package_details as pd ON p.package_id=pd.package_id WHERE p.package_status=1 and pd.lang_id=' + req.body.language, function(err, results) {
        if (!err) {
            console.log(err);
            var result = JSON.parse(JSON.stringify(results))
            var resarry = [];
            if (result.length > 0) {
                for (var k of result) {
                    k.package_image = pakg_adver_url + k.package_image;

                    resarry.push(k)
                }

                res.send({
                    'status': 1,
                    'message': constant.ALLP,
                    'data': resarry
                })
            } else {
                res.send({
                    'status': 0,
                    'message': constant.PNOTF

                })
            }
        } else {
            res.send({
                'status': 0,
                'message': constant.NODATAFOUND

            })
        }

    })

});
app.post('/Checkmypackage', (req, res) => {
    var user_pub_id = req.body.pub_id;

    if (!user_pub_id) {
        res.send({ 'status': 0, 'message': constant.UNOTF });
    } else {

        db.query('SELECT * FROM subscription_history   WHERE user_pub_id="' + user_pub_id + '" AND subs_status=1 ORDER BY subs_id DESC', function(err, results) {
            if (!err) {
                var packagearray = [];
                var result = JSON.parse(JSON.stringify(results))

                // console.log('current date======',currdate);
                // console.log('end date=====',enddate);

                if (result.length == 0) {
                    res.send({
                        'status': 0,
                        'message': constant.USHNF,
                    })

                } else {
                    var k = result[0];

                    var myrow = k.row_data
                    var resultparse = JSON.parse(myrow);
                    k.row_data = resultparse;
                    k.row_data.package_image = pakg_adver_url + k.row_data.package_image

                    var days_diff = Math.round((k.subs_end_date - moment().valueOf()) / (86400 * 1000));
                    k.days_remaining = (days_diff >= 0) ? days_diff : 0;
                    packagearray = k;

                    res.send({
                        'status': 1,
                        'message': constant.UPIA,
                        'package_detial': packagearray
                    })

                }

            } else {
                res.send({
                    'status': 0,
                    'message': constant.SWRON

                })
            }
        })
    }
});

Date.prototype.addDays = function(days) {
    var date = new Date(this.valueOf());
    date.setDate(date.getDate() + days);
    return date;
}

app.post('/SubscribUser', (req, res) => {
    var user_pub_id = req.body.user_pub_id;
    var package_pub_id = req.body.package_pub_id;
    var trans_id = req.body.transaction_id;
    var order_id = req.body.order_id;
    var paytab_order_id = req.body.paytab_order_id;

    if (user_pub_id && package_pub_id && trans_id && order_id && paytab_order_id) {
        const axios = require('axios');
        var querystring = require('qs');
        var objData = {
            'merchant_email': 'admin@ekeymarket.com',
            'secret_key': 'AzX5NhNvAwZ7BU0kkiU291LXvViEUBovblBYDoudVtlxnlRIEMKNNvKjr3XmFmRQIsPlRjzNNVkagbTVXDIL9t4Aw2WcpN28gSu8',
            'transaction_id': trans_id,
            'order_id': order_id
        };
        axios.post("https://www.paytabs.com/apiv2/verify_payment_transaction", querystring.stringify(objData))
            .then(function(response) {

                if (response.data.response_code != 100) {
                    //response.status = 0;
                    //response.message = response.data.result;

                    res.status(200).json({ status: 0, message: "No Transaction found" });
                } else {
                    var update_trans = {
                        paytab_order_id: req.body.paytab_order_id,
                        paytab_trans_id: req.body.paytab_trans_id,
                        token_customer_email: req.body.token_customer_email,
                        token_customer_password: req.body.token_customer_password,
                        token: req.body.token,
                        status: 1,
                        payment_status: 1
                    };
                    db.query('UPDATE transactions set ? WHERE trans_id="' + paytab_order_id + '"', update_trans, function(err, results) {
                        if (err) {
                            console.log(err);
                            error_response(res, err);
                            return;
                        }
                        db.query('SELECT p.*,pd.package_title,pd.package_discription FROM package as p JOIN package_details as pd ON pd.package_id=pd.package_id WHERE p.package_id="' + package_pub_id + '" AND p.package_status=1 AND pd.lang_id=' + req.body.language, function(err, results) {
                            //db.query('SELECT * FROM package WHERE package_id="'+package_pub_id+'" AND package_status=1',function(err,results){
                            if (!err) {
                                var result = JSON.parse(JSON.stringify(results))
                                if (result.length > 0) {
                                    var row_data = {
                                        "package_id": result[0].package_id,
                                        "package_title": result[0].package_title,
                                        //"package_title_ar": result[0].package_title_ar,
                                        "package_discription": result[0].package_discription,
                                        //"package_discription_ar": result[0].package_discription_ar,
                                        "package_image": result[0].package_image,
                                        "package_amount": result[0].package_amount,
                                        "currency_code": result[0].currency_code,
                                        "package_days": result[0].package_days,
                                        "package_created_at": result[0].package_created_at,
                                        "package_updated_at": result[0].package_updated_at,
                                        "package_status": result[0].package_status
                                    }
                                    var myrow = JSON.stringify(row_data)
                                        // res.send(myrow)
                                    var days = result[0].package_days;
                                    var currdate = (new Date()).valueOf().toString();
                                    //currdate = moment(currdate).format("YYYY-MM-DD");
                                    //var end_date = moment(currdate, "DD-MM-YYYY").add(days, 'days');
                                    var end_date = (new Date()).addDays(days).valueOf().toString();
                                    var EndDate = JSON.parse(JSON.stringify(end_date))

                                    //   var Enddate = new Date();
                                    // Enddate.setDate(Enddate.getDate() + days);

                                    var package_title = result[0].package_title;
                                    var package_discription = result[0].package_discription;
                                    var package_image = result[0].package_image;
                                    var package_amount = result[0].package_amount;
                                    var package_days = result[0].package_days;

                                    var subsdata = {
                                        'user_pub_id': user_pub_id,
                                        'package_pub_id': package_pub_id,
                                        'subs_start_date': currdate,
                                        'subs_end_date': EndDate,
                                        'subs_amount': package_amount,
                                        'subs_title': package_title,
                                        'subs_days': days,
                                        'subs_created_at': currdate,
                                        'row_data': myrow
                                    }

                                    db.query('INSERT INTO subscription_history SET ?', subsdata, function(err, subscribresult) {
                                        if (!err) {
                                            db.query('UPDATE user SET subscription_end_date="' + EndDate + '" WHERE pub_id="' + user_pub_id + '"', function(err, results) {});
                                            db.query('UPDATE product SET subscription_end_date="' + EndDate + '" WHERE user_pub_id="' + user_pub_id + '"', function(err, results) {});
                                            var packgdetial = [];
                                            db.query('SELECT * FROM subscription_history   WHERE user_pub_id="' + user_pub_id + '" AND subs_status=1 ORDER BY subs_id DESC', function(err, pkgresults) {
                                                var result = JSON.parse(JSON.stringify(pkgresults))
                                                if (result.length == 0) {
                                                    res.send({
                                                        'status': 0,
                                                        'message': constant.USHNF,
                                                    })

                                                } else {
                                                    var k = result[0];

                                                    var myrow = k.row_data
                                                    var resultparse = JSON.parse(myrow);
                                                    k.row_data = resultparse;
                                                    k.row_data.package_image = pakg_adver_url + k.row_data.package_image
                                                        /*var days = k.subs_days;
                                                        var currdate = new Date();
                                                        currdate = moment(currdate).format("YYYY-MM-DD");
                                                        var enddate = k.subs_end_date;
                                                        enddate = moment(enddate).format("YYYY-MM-DD");
                                                        var isd = moment(enddate).isSameOrAfter(currdate);
                                                        console.log(isd);*/

                                                    //k.subs_start_date = moment(currdate).unix(),
                                                    //k.subs_end_date = moment(EndDate).unix(),

                                                    packgdetial = k;


                                                    res.send({
                                                        'status': 1,
                                                        'message': constant.USS,
                                                        'package_detial': packgdetial
                                                    })
                                                }

                                            })
                                        } else {
                                            console.log(err);
                                            error_response(res, err);
                                        }
                                    });
                                } else {
                                    res.send({
                                        'status': 0,
                                        'message': constant.NODATAFOUND
                                    })
                                }
                            } else {
                                console.log(err);
                                error_response(res, err);
                            }
                        })
                    });

                }
            })
            .catch(function(err) {
                console.log(err);
                error_response(res, err);
            });
    } else {
        res.send({
            'status': 0,
            'message': constant.INPUTWRONG
        })
    }
});

function error_response(res, message) {
    res.send({
        'status': 0,
        'message': message
    })
}
app.post('/createTransaction', (req, res) => {
    var user_pub_id = req.body.user_pub_id;
    var package_pub_id = req.body.package_pub_id;
    var subsstartdate = new Date();

    //trans_id order_id user_pub_id   package_pub_id  gateway_trans_id token_customer_email token_customer_password
    //token status payment_status created_at updated_at 
    if (user_pub_id && package_pub_id) {
        db.query('SELECT p.*,pd.package_title,pd.package_discription FROM package as p JOIN package_details as pd ON pd.package_id=pd.package_id WHERE p.package_id="' + package_pub_id + '" AND p.package_status=1 AND pd.lang_id=' + req.body.language, function(err, results) {
            if (!err) {
                var result = JSON.parse(JSON.stringify(results))
                if (result.length > 0) {
                    var random = Math.random().toString(16);
                    var order_id = crypto.createHash('sha1').update(random + current_date).digest('hex');
                    var current_date = (new Date()).valueOf().toString();
                    var row_data = {
                        "order_id": order_id,
                        "user_pub_id": user_pub_id,
                        "package_pub_id": package_pub_id,
                        "created_at": current_date,
                        "updated_at": current_date
                    }

                    db.query('INSERT INTO transactions SET ?', row_data, function(err, trans_data) {
                        if (!err) {
                            res.send({
                                'status': 1,
                                'message': "Transaction created successfully",
                                'order_id': order_id
                            })
                        } else {
                            console.log(err);
                            error_response(res, err);
                        }
                    });
                } else {
                    res.send({
                        'status': 0,
                        'message': constant.NODATAFOUND
                    })
                }
            } else {
                console.log(err);
                error_response(res, err);
            }

        })
    } else {
        res.send({
            'status': 0,
            'message': constant.INPUTWRONG

        })
    }
})

app.post('/getMySubscriptionHistory', (req, res) => {
    var user_pub_id = req.body.pub_id;


    if (!user_pub_id) {
        res.send({ 'status': 0, 'message': constant.INPUTWRONG });
    } else {

        db.query('SELECT * FROM subscription_history WHERE user_pub_id="' + user_pub_id + '" AND subs_status=1 order by subs_id asc', function(err, results) {
            if (!err) {
                var historyarray = []
                var result = JSON.parse(JSON.stringify(results))
                for (var k of result) {
                    var myrow = k.row_data
                    var resultparse = JSON.parse(myrow);
                    k.row_data = resultparse
                        //console.log(k)
                    var allhistry = {
                        "subs_id": k.subs_id,
                        "user_pub_id": k.user_pub_id,
                        "package_pub_id": k.package_pub_id,
                        "subs_start_date": k.subs_start_date,
                        "subs_end_date": k.subs_end_date,
                        "subs_amount": k.subs_amount,
                        "subs_title": k.subs_title,
                        "subs_description": k.row_data.package_discription,
                        "row_data": k.row_data,
                        "subs_days": k.subs_days,
                        "subs_created_at": k.subs_created_at,
                        "subs_status": k.subs_status

                    }
                    historyarray.push(allhistry)


                }
                if (result.length > 0) {
                    res.send({
                        'status': 1,
                        'message': constant.ALLSUBSHTRY,
                        'packagedetial': historyarray.reverse()
                    })
                } else {
                    res.send({
                        'status': 0,
                        'message': constant.SUBSHNOTF,

                    })
                }


            } else {
                res.send({
                    'status': 0,
                    'message': SOMEWRONG,

                })
            }

        })
    }

});




app.post("/Discoverdata", function(req, res) {
    if (!req.body.user_pub_id || !req.body.latitude || !req.body.longitude || !req.body.radius) {
        res.send({
            'status': 0,
            'message': constant.UREQALLFILD
        })
    } else {
        var latitude = req.body.latitude;
        var longitude = req.body.longitude;
        var radius = req.body.radius;
        var language = req.headers.language;
        var language = req.body.language;
        var newarr = [];
        var advarr = [];


        var advertsql = "select * from advertisement as a join advertisement_detail as ad where a.status='1' and ad.lang_id=" + req.body.language;

        con.query(advertsql, function(err, advertisement_result) {
            console.log(err);
            var advertisements = JSON.parse(JSON.stringify(advertisement_result))
            advertisements.forEach(function(key, i, inner_callback) {

                key.ad_banner = bannerImage_path + key.image;

                advarr.push(key)
            })

        });

        cm.getCategoryWithLanguage(req.body.language, 'category', null, function(err, AllCat) {
            AllCat
                .reduce(function(promiesRes, k, index) {
                    return promiesRes
                        .then(function(data) {

                            return new Promise(function(resolve, reject) {
                                if (typeof req.body.keyword != "undefined") {
                                    finalStr = (req.body.keyword).split(/[ ,]+/).join(',');
                                    var searchArr = _.split(finalStr, ",");
                                    //console.log(searchArr);
                                    //var searchArr = (req.body.keyword).split("");
                                } else {
                                    var searchArr = [];
                                }
                                my.getSearchKeywordDataWithoutTag(req.body.latitude, req.body.longitude, 'product', { "category_pub_id": k.pub_id }, searchArr, req.body.user_pub_id, req.body.radius, function(err, productData) {
                                    if (typeof productData != "undefined") {
                                        searchResponseCar(productData, req.body.user_pub_id, req.body.language, function(final_result) {
                                            if (final_result.length > 0) {
                                                newarr.push({
                                                    'title': k.category_name,
                                                    'icon': k.cat_icon,
                                                    'description': k.description,
                                                    'data': final_result
                                                });
                                            }
                                            resolve(final_result);
                                        });
                                    }
                                });
                            });
                        })
                        .catch(function(error) {
                            res.send({
                                "status": 0,
                                "message": constant.INTERNAL_ERROR
                            });
                            return error.message;
                        })
                }, Promise.resolve(null)).then(arrayOfResults => {
                    res.send({
                        "status": 1,
                        "message": constant.PRODUCTS,
                        "DiscoverData": newarr,
                        "advertisement_data": advarr
                    });
                });
        });
    }
});
app.post("/frontMailer", function(req, res) {

    var html = '<div><b>Name:</b><p>' + req.body.name + '</p><b>Email:</b><p>' + req.body.email + '</p><b>Mobile:</b><p>' + req.body.phone + '</p><b>Company:</b><p>' + req.body.company + '</p><b>Message:</b><p>' + req.body.message + '</p></div>';
    var api_key = '8f3175b39b9bf12d1ef673c91ade4a90-f8faf5ef-72773d7a';
    var domain = 'mg.ekeymarket.com';
    var mailgun = require('mailgun-js')({ apiKey: api_key, domain: domain });

    var data = {
        from: req.body.email,
        to: 'admin@ekeymarket.com',
        subject: "Keymarket | new contact message",
        //text: req.body.message,
        html: html
    };

    mailgun.messages().send(data, function(error, body) {
        if (!error && next) {
            next(body);
        } else {
            console.log(error);
        }
    });

})