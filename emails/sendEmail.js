import nodemailer from 'nodemailer';

export async function sendEmail(to, subject, text) {
  const transporter = nodemailer.createTransport({
    host: 'smtp.gmail.com',
    port: 587, // ✅ Use 587 for TLS (more reliable)
    secure: false, // ✅ false for port 587 (true for 465)
    auth: {
      user: process.env.EMAIL_USER,
      pass: process.env.EMAIL_PASS, // ✅ Must be Gmail App Password
    },
  });

  const mailOptions = {
    from: `"Your Store" <${process.env.EMAIL_USER}>`,
    to,
    subject,
    text,
  };

  await transporter.sendMail(mailOptions);
}
