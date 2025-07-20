const nodemailer = require('nodemailer');

const transporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: process.env.EMAIL_PORT,
  secure: false, // true pour 465, false pour 587
  auth: {
    user: process.env.EMAIL_USER,
    pass: process.env.EMAIL_PASS,
  },
});

async function sendOtpEmail(email, otp) {
  await transporter.sendMail({
    from: `"Mini-Wallet" <${process.env.EMAIL_USER}>`,
    to: email,
    subject: 'Votre code OTP pour l\'inscription',
    text: `Votre code OTP est : ${otp}. Il expire dans 5 minutes.`,
    html: `<p>Votre code OTP est : <b>${otp}</b>. Il expire dans 5 minutes.</p>`,
  });
}

module.exports = { sendOtpEmail };