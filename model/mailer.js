const nodemailer = require('nodemailer');
class Mailer {
    constructor() {
        //console.log(process.env);
        this.transporter = nodemailer.createTransport({
            service: "smtp.mailgun.org", //name of email provider
            auth: {
                user: "postmaster@sandboxf1cfa8872d2a4eaf904b739ebbd9ba67.mailgun.org", // sender's gmail id
                pass: "9c36a0356cc90cc17347629dec4e0f53-52b6835e-9c917e0b" // sender password
            }
        });
        this.mailOptions = {
            from: // sender's gmail
        };
    }

    send(to_email, subject, html, next) {
        this.mailOptions.to = to_email;
        this.mailOptions.subject = subject;
        this.mailOptions.html = html;
        this.transporter.sendMail(this.mailOptions, function(error, info) {
            if (error) {
                console.log("error is mail sending", error);
            } else {
                console.log('Email sent: ' + info.response);
            }
            next(error, info);
        });
    }

}

module.exports = Mailer;