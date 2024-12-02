const config = require('./config')

const createVerificationEmail = (name, email, url) => {
    const msg = {
        to: email,
        from: config.FROM_EMAIL,
        subject: 'Verifica tu cuenta de Pensiona-T',
        html: `
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Verifica tu cuenta de Pensiona-T</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333333; margin: 0; padding: 0;">
                <table role="presentation" style="width: 100%; border-collapse: collapse;">
                <tr>
                    <td style="padding: 0;">
                    <table role="presentation" style="width: 100%; max-width: 600px; margin: 0 auto; background-color: #ffffff;">
                        <!-- Header -->
                        <tr>
                        <td style="background-color: #0c4a6e; padding: 20px; text-align: center;">
                            <h1 style="color: #ffffff; margin: 0; font-size: 24px;">Pensiona-T</h1>
                        </td>
                        </tr>
                        <!-- Content -->
                        <tr>
                        <td style="padding: 40px 30px;">
                            <h2 style="color: #0c4a6e; margin-top: 0;">Bienvenid@, ${name}!</h2>
                            <p style="margin-bottom: 20px;">Gracias por registrarte en Pensiona-T. Por favor, verifica tu dirección de correo electrónico haciendo clic en el siguiente botón:</p>
                            <table role="presentation" style="width: 100%;">
                            <tr>
                                <td style="text-align: center;">
                                <a href="${url}" style="display: inline-block; background-color: #0ea5e9; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 4px; font-weight: bold;">Verificar cuenta</a>
                                </td>
                            </tr>
                            </table>
                            <p style="margin-top: 30px; font-size: 14px; color: #666666;">Si no te has registrado en nuestro sitio, puedes ignorar este correo.</p>
                        </td>
                        </tr>
                        <!-- Footer -->
                        <tr>
                        <td style="background-color: #f3f4f6; padding: 20px; text-align: center;">
                            <p style="margin: 0; font-size: 12px; color: #666666;">© ${new Date().getFullYear()} Pensiona-T</p>
                        </td>
                        </tr>
                    </table>
                    </td>
                </tr>
                </table>
            </body>
            </html>
        `,
    }
    
    return msg
}

const createRecoveryEmail = (name, email, url) => {
    const msg = {
        to: email,
        from: config.FROM_EMAIL,
        subject: 'Recupera tu contraseña en Pensiona-T',
        html: `
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>Recupera tu cuenta de Pensiona-T</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333333; margin: 0; padding: 0;">
                <table role="presentation" style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 0;">
                            <table role="presentation" style="width: 100%; max-width: 600px; margin: 0 auto; background-color: #ffffff;">
                                <!-- Header -->
                                <tr>
                                    <td style="background-color: #0c4a6e; padding: 20px; text-align: center;">
                                        <h1 style="color: #ffffff; margin: 0; font-size: 24px;">Pensiona-T</h1>
                                    </td>
                                </tr>
                                <!-- Content -->
                                <tr>
                                    <td style="padding: 40px 30px;">
                                        <h2 style="color: #0c4a6e; margin-top: 0;">Hola, ${name}!</h2>
                                        <p style="margin-bottom: 20px;">Recibimos una solicitud para restablecer tu cuenta de Pensiona-T. Para continuar, haz clic en el botón de abajo:</p>
                                        <table role="presentation" style="width: 100%;">
                                            <tr>
                                                <td style="text-align: center;">
                                                    <a href="${url}" style="display: inline-block; background-color: #0ea5e9; color: #ffffff; text-decoration: none; padding: 12px 24px; border-radius: 4px; font-weight: bold;">Restablece tu cuenta</a>
                                                </td>
                                            </tr>
                                        </table>
                                        <p style="margin-top: 30px; font-size: 14px; color: #666666;">Si no solicitaste restablecer tu cuenta, puedes ignorar este correo. Tu contraseña no será cambiada sin tu confirmación.</p>
                                    </td>
                                </tr>
                                <!-- Footer -->
                                <tr>
                                    <td style="background-color: #f3f4f6; padding: 20px; text-align: center;">
                                        <p style="margin: 0; font-size: 12px; color: #666666;">© ${new Date().getFullYear()} Pensiona-T</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
            </html>
        `,
    }
    
    return msg
}

const createGeneralEmail = (subject, message) => {
    const msg = {
        from: config.FROM_EMAIL,
        subject: subject,
        html: `
            <!DOCTYPE html>
            <html lang="es">
            <head>
                <meta charset="UTF-8">
                <meta name="viewport" content="width=device-width, initial-scale=1.0">
                <title>${subject}</title>
            </head>
            <body style="font-family: Arial, sans-serif; line-height: 1.6; color: #333333; margin: 0; padding: 0;">
                <table role="presentation" style="width: 100%; border-collapse: collapse;">
                    <tr>
                        <td style="padding: 0;">
                            <table role="presentation" style="width: 100%; max-width: 600px; margin: 0 auto; background-color: #ffffff;">
                                <!-- Header -->
                                <tr>
                                    <td style="background-color: #0c4a6e; padding: 20px; text-align: center;">
                                        <h1 style="color: #ffffff; margin: 0; font-size: 24px;">Pensiona-T</h1>
                                    </td>
                                </tr>
                                <!-- Content -->
                                <tr>
                                    <td style="padding: 40px 30px;">
                                        ${message}
                                    </td>
                                </tr>
                                <!-- Footer -->
                                <tr>
                                    <td style="background-color: #f3f4f6; padding: 20px; text-align: center;">
                                        <p style="margin: 0; font-size: 12px; color: #666666;">© ${new Date().getFullYear()} Pensiona-T</p>
                                    </td>
                                </tr>
                            </table>
                        </td>
                    </tr>
                </table>
            </body>
            </html>
        `,
    }
    
    return msg
}

module.exports = {
    createVerificationEmail,
    createRecoveryEmail,
    createGeneralEmail
}