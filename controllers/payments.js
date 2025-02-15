const paymentsRouter = require('express').Router()
const axios = require('axios')
const { MercadoPagoConfig, Preference } = require('mercadopago')
const config = require('../utils/config')
const { verifyToken } = require('../utils/middleware')
const User = require('../models/user') 
const Payment = require('../models/payment') 
const PreferenceModel = require('../models/preference')
const WebhookNotification = require('../models/webhookNotification')
const { v4: uuidv4 } = require('uuid')
const sgMail = require('@sendgrid/mail')
const { createPaymentConfirmationEmail } = require('../utils/emailTemplates')

sgMail.setApiKey(config.SENDGRID_API_KEY)

const mercadopago = new MercadoPagoConfig({
    accessToken: config.MERCADOPAGO_ACCESS_TOKEN, 
})

// Crear una preferencia de pago en MercadoPago
paymentsRouter.post('/api/create_preference', verifyToken, async (req, res) => {
    try {
        const externalReference = uuidv4() // Genera un identificador único

        const body = {
            items: [
                {
                    id: externalReference,
                    title: req.body.title,
                    description: req.body.title,
                    quantity: req.body.quantity,
                    currency_id: 'MXN',
                    unit_price: req.body.unit_price,
                },
            ],
            payer: {
                email: req.user.email,
            },
            back_urls: {
                success: "https://www.pensiona-t.com/status",
                failure: "https://www.pensiona-t.com/status",
                pending: "https://www.pensiona-t.com/status",
            },
            auto_return: 'approved',
            payment_methods: {
                excluded_payment_types: [
                    { id: 'ticket' },         // Excluye pagos en efectivo (OXXO, etc.)
                    { id: 'bank_transfer' },  // Excluye transferencias bancarias
                    { id: 'atm' }             // Excluye pagos en cajeros automáticos
                ],
                installments: 1,            // Número de meses sin intereses
            },
            notification_url: `${config.URL_WEBHOOK}/api/payments/webhook?source_news=webhooks`,
            statement_descriptor: 'PENSIONA-T',
            external_reference: externalReference,
        }

        const preference = new Preference(mercadopago)
        const result = await preference.create({ body })
        
        // Guardar la preferencia en la base de datos
        const newPreference = new PreferenceModel({
            preference_id: result.id,
            external_reference: externalReference,
            email: req.user.email,
            items: body.items,
            total_amount: body.items.reduce((sum, item) => sum + (item.unit_price * item.quantity), 0),
            currency_id: body.items[0].currency_id,
            statement_descriptor: body.statement_descriptor,
            status: 'pending',
            date_created: new Date(),
            expires: body.expires || false,
            date_of_expiration: body.date_of_expiration || null,
            init_point: result.init_point,
            sandbox_init_point: result.sandbox_init_point,
            back_urls: body.back_urls,
            notification_url: body.notification_url,
        })

        await newPreference.save()

        res.json({ id: result.id })
    } catch (error) {
        console.error('Error al crear la preferencia:', error.response?.data || error)
        res.status(500).json({ success: false, message: 'Error en el servidor', error: error.message })
    }
})

// Webhook para recibir notificaciones de MercadoPago
paymentsRouter.post('/api/payments/webhook', async (req, res) => {
    const payment = req.body

    try {
        // Guardar la notificación en la base de datos
        await WebhookNotification.create({
            action: payment.action,
            api_version: payment.api_version,
            data: { id: payment.data.id },
            date_created: payment.date_created,
            notification_id: payment.id,
            live_mode: payment.live_mode,
            type: payment.type,
            user_id: payment.user_id,
        })

        if (payment.action === 'payment.created' || payment.action === 'payment.updated') {
            // Obtener información del pago desde MercadoPago
            const paymentInfo = await axios.get(`https://api.mercadopago.com/v1/payments/${payment.data.id}`, {
                headers: {
                    Authorization: `Bearer ${config.MERCADOPAGO_ACCESS_TOKEN}`,
                },
            })

            const { id, status, transaction_amount, external_reference } = paymentInfo.data

            // Guardar o actualizar el pago en la base de datos
            const updatedPayment = await Payment.findOneAndUpdate(
                { paymentId: id },
                {
                    paymentId: id,
                    status,
                    amount: transaction_amount,
                    external_reference,
                },
                { upsert: true, new: true }
            )

            console.log(`Pago ${id} actualizado: ${status}`)

            // Buscar el email correcto en Preference usando external_reference
            const preference = await PreferenceModel.findOne({ external_reference })

            if (!preference) {
                console.log(`No se encontró Preference con external_reference: ${external_reference}`)
                return res.sendStatus(200)
            }

            const userEmail = preference.email

            // Si el pago está aprobado, actualizar la suscripción del usuario
            if (status === 'approved') {
                const user = await User.findOne({ email: userEmail })

                if (user) {
                    let newSubscription 
                    const currentDate = new Date()
                    let newExpiration = new Date(currentDate.setDate(currentDate.getDate() + 30))

                    // Verificamos el monto y asignamos la nueva suscripción
                    if (transaction_amount === 199) {
                        newSubscription = 'unlimited'
                    } else if (transaction_amount === 149) {
                        newSubscription = 'pro'
                    }

                    user.subscription = newSubscription
                    user.expiration = newExpiration
                    await user.save()

                    const paymentEmail = createPaymentConfirmationEmail(user.name, user.email, newSubscription, newExpiration, external_reference)
                    await sgMail.send(paymentEmail)

                    console.log(`Usuario ${user.email} actualizado: suscripción ${newSubscription}, vence el ${newExpiration}`)
                }
            }

            // Si el pago fue devuelto, actualizar la suscripción del usuario
            if (status === 'refunded') {
                const user = await User.findOne({ email: userEmail })

                if (user) {
                    user.subscription = 'free'
                    await user.save()

                    console.log(`Usuario ${user.email} actualizado: suscripción free`)
                }
            }
        }

        res.sendStatus(200)
    } catch (error) {
        console.error('Error en el webhook de MercadoPago:', error)
        res.sendStatus(500)
    }
})

module.exports = paymentsRouter
