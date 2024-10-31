import type { TransportOptions } from 'nodemailer'
import nodemailer from 'nodemailer'

const config = useRuntimeConfig()
const transporter = nodemailer.createTransport({
  host: config.emailHost,
  port: config.emailPort,
  secure: false,
  auth: {
    user: config.emailUser,
    pass: config.emailPassword
  },
  tls: {
    // do not fail on invalid certs
    rejectUnauthorized: false
  }
} as TransportOptions)
export default transporter

async function sendEmail(to: string, subject: string, text: string) {
  try {
    await transporter.sendMail({
      from: 'nuxtauth' + '<' + config.emailUser + '>',
      to,
      replyTo: 'orders@arbaminimsa.co.za',
      subject,
      html: text
    })
  } catch (error: unknown) {
    console.error(error)
  }
}
export { sendEmail }
