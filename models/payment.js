const mongoose = require('mongoose')

const paymentSchema = new mongoose.Schema({
    paymentId: { type: String, required: true, unique: true }, // ID de MercadoPago
    email: { type: String, required: true }, // Correo del pagador
    amount: { type: Number, required: true }, // Monto del pago
    status: { type: String, required: true, enum: ['pending', 'approved', 'rejected', 'in_process', 'cancelled', 'refunded'] }, // Estado del pago
    paymentMethod: { type: String }, // Método de pago (ej. "credit_card", "debit_card", "pix")
    paymentType: { type: String }, // Tipo de pago (ej. "ticket", "bank_transfer", "digital_currency")
    transactionDate: { type: Date, default: Date.now }, // Fecha de la transacción
    orderId: { type: String }, // ID de la orden de pago en MercadoPago
    payerId: { type: String }, // ID del pagador en MercadoPago
    payerFirstName: { type: String }, // Nombre del pagador
    payerLastName: { type: String }, // Apellido del pagador
    payerIdentificationType: { type: String }, // Tipo de identificación (DNI, CPF, etc.)
    payerIdentificationNumber: { type: String }, // Número de identificación
    additionalInfo: { type: mongoose.Schema.Types.Mixed }, // Campo para almacenar información extra si es necesario
    external_reference: { type: String }, // Referencia externa
}, { timestamps: true })

const Payment = mongoose.model('Payment', paymentSchema)

module.exports = Payment
