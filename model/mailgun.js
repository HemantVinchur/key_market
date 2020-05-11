var api_key = '8f3175b39b9bf12d1ef673c91ade4a90-f8faf5ef-72773d7a';
var domain = 'mg.ekeymarket.com';
var mailgun = require('mailgun-js')({apiKey: api_key, domain: domain});

module.exports.send  = function(to,subject,html, next){
    var data = {
    from: 'Key Market <no-reply@ekeymarket.com>',
    to: to,
    subject: subject,
    text: 'Testing some Mailgun awesomeness!',
    html: html
    };
    
    mailgun.messages().send(data, function (error, body) {
        if(!err){
            next(body);
        }else{
            console.log(err);
        }
    });

}