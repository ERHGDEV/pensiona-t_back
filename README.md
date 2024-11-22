# Pensiona-T Back-End

Pensiona-T Back-End es el sistema de backend para la plataforma Pensiona-T, diseñado para gestionar y optimizar la administración de pensiones. Este proyecto proporciona servicios de autenticación, gestión de usuarios, control de accesos y manejo seguro de datos relacionados con el sistema de pensiones.

## Características

- Autenticación y autorización de usuarios mediante JWT.
- Gestión de roles y permisos.
- Creación, actualización, y eliminación de usuarios.
- API REST para la interacción con la base de datos.
- Integración segura con bases de datos MongoDB.
- Límite de peticiones por usuario para evitar abusos del sistema.
- Middleware para manejo de errores y registro de peticiones.
- Sistema centralizado de registro de información y errores.

## Instalación

Sigue estos pasos para configurar el proyecto en tu entorno local:

1. Clona el repositorio:
    ```bash
    git clone https://github.com/yourusername/pensiona-t_back.git
    ```
2. Navega al directorio del proyecto:
    ```bash
    cd pensiona-t_back
    ```
3. Instala las dependencias:
    ```bash
    pnpm install
    ```
4. Configura las variables de entorno creando un archivo `.env` 
    ```bash
    # Configuración del servidor
    PORT= El puerto en el que se ejecuta el servidor. (5000)

    # Configuración de la base de datos
    MONGODB_URI=URL de conexión a la base de datos MongoDB.

    # Configuración del correo electrónico y API de SendGrid
    SENDGRID_API_KEY=API Key para la integración con SendGrid, que se utiliza para el envío de correos electrónicos.
    FROM_EMAIL=Dirección de correo electrónico que se utiliza como remitente en los correos electrónicos enviados desde la plataforma.

    # Configuración del JWT
    JWT_SECRET=Clave secreta utilizada para firmar y verificar los tokens JSON Web (JWT).
    JWT_EXPIRES_IN=Tiempo de expiración de los JWT utilizados para la autenticación.
    JWT_REGISTER_EXPIRES_IN=Tiempo de expiración de los JWT específicamente para la verificación de nuevos registros.
    JWT_RESET_PASSWORD_EXPIRES_IN=Tiempo de expiración de los JWT utilizados para la recuperación de contraseñas.

    # URL del frontend
    URL_FRONTEND=URL de la aplicación frontend asociada con la plataforma Pensiona-T.
    ```
5. Ejecuta la aplicación:
    ```bash
    pnpm run dev
    ```

## Uso

Después de la instalación, el servidor back-end estará funcionando en `http://localhost:5000`. Puedes usar herramientas como Postman para interactuar con las APIs.

### Logger Utilizado en la Aplicación
El proyecto incluye un módulo de registro (`logger`) para manejar la salida de información y errores en la consola, permitiendo una depuración más sencilla y la separación clara de logs informativos y errores.

#### Estructura del módulo `logger`
El archivo logger.js contiene dos funciones principales:

1. `info`:

- Descripción: Función que se utiliza para registrar información general en la consola, como detalles sobre la ejecución de procesos o confirmaciones exitosas.
- **Uso típico**: Registrar eventos normales del sistema.

```bash
const { info } = require('./utils/logger');
info('Servidor iniciado en el puerto 3000');
```

2. `error`: 

- Descripción: Función que se utiliza para registrar errores en la consola. Utiliza `console.error` para asegurarse de que los errores se destaquen.
- **Uso típico**: Registrar errores del sistema o excepciones.

```bash
const { error } = require('./utils/logger');
error('Error al conectarse a la base de datos');
```

##### Ejemplos de Uso
Dentro de otros módulos, puedes utilizar las funciones `info` y `error` para mantener registros claros:

```bash
const logger = require('./utils/logger');

// Ejemplo de uso en el servidor
logger.info('El servidor se ha iniciado correctamente');
logger.error('No se pudo conectar a la base de datos');

// Uso dentro de un middleware
app.use((req, res, next) => {
    logger.info('Nueva solicitud recibida:', req.method, req.path);
    next();
});
```

### Middleware Utilizado en la Aplicación
El proyecto incluye varios middlewares que son esenciales para su funcionamiento. Aquí hay una descripción de cada uno:

1. `requestLogger`:

- **Descripción**: Middleware que registra detalles sobre cada solicitud entrante, incluyendo el método HTTP, la ruta solicitada y el cuerpo de la petición.
- **Uso típico**: Proporciona visibilidad sobre las peticiones realizadas al servidor, útil para depuración.

    ```bash
    const { requestLogger } = require('./utils/middleware');
    app.use(requestLogger);
    ```

2. `unknownEndpoint`:

- **Descripción**: Middleware que maneja las solicitudes a rutas no existentes, devolviendo un error 404.
- **Uso típico**: Se utiliza al final de todas las rutas definidas para capturar peticiones a endpoints desconocidos.

    ```bash
    const { unknownEndpoint } = require('./utils/middleware');
    app.use(unknownEndpoint);
    ```

3. `errorHandler`:

- **Descripción**: Middleware para la gestión centralizada de errores. Captura y maneja errores específicos como `CastError`, `ValidationError`, y `JsonWebTokenError`.
- **Uso típico**: Maneja errores comunes y retorna respuestas significativas al cliente.

    ```bash
    const { errorHandler } = require('./utils/middleware');
    app.use(errorHandler);
    ```

4. `checkAndUpdateUserStatus`:

- **Descripción**: Función que verifica el estado del usuario basado en su fecha de expiración y actualiza su estado si es necesario.
- **Uso típico**: Mantiene actualizada la información del estado del usuario, como activo o inactivo.

    ```bash
    const { checkAndUpdateUserStatus } = require('./utils/middleware');
    ```

5. `verifyToken`:

- **Descripción**: Middleware que verifica la validez de un token JWT proporcionado en los encabezados de la solicitud.
- **Uso típico**: Se utiliza para proteger rutas privadas que requieren autenticación.

    ```bash
    const { verifyToken } = require('./utils/middleware');
    app.use('/ruta-protegida', verifyToken);
    ```

6. `verifyAdmin`:

- **Descripción**: Middleware que verifica si el usuario autenticado tiene permisos de administrador.
- **Uso típico**: Protege rutas que solo pueden ser accedidas por usuarios con el rol de administrador.

    ```bash
    const { verifyAdmin } = require('./utils/middleware');
    app.use('/ruta-admin', verifyToken, verifyAdmin);
    ```

7. `limiter`:

- **Descripción**: Middleware que limita el número de solicitudes que un usuario puede realizar en un periodo de tiempo. Configurado para permitir un máximo de 100 solicitudes cada 15 minutos por IP.
- **Uso típico**: Evita el abuso de la API con múltiples solicitudes en un corto periodo de tiempo.

    ```bash
    const { limiter } = require('./utils/middleware');
    app.use(limiter);
    ```

### Generación de Correos Electrónicos Aleatorios
El proyecto incluye una utilidad para generar correos electrónicos aleatorios, que puede ser especialmente útil durante la fase de pruebas, permitiendo la creación rápida de correos electrónicos ficticios.

#### Estructura del módulo ``generarEmailAleatorio``
El archivo `generarEmailAleatorio.js `contiene una función que genera un correo electrónico aleatorio combinando letras y números, seguido del dominio @gmail.com.

1. Función `generarEmailAleatorio`
- **Descripción**: Genera un correo electrónico aleatorio compuesto por 10 caracteres alfabéticos aleatorios seguidos de 2 dígitos numéricos. El correo generado utiliza el dominio @gmail.com.
- **Uso típico**: Se utiliza en pruebas automáticas o manuales donde se necesita un correo electrónico único y aleatorio.

```bash
Copiar código
const { generarEmailAleatorio } = require('./utils/emailUtils');

const nuevoEmail = generarEmailAleatorio();
console.log('Correo generado:', nuevoEmail);
// Posible salida: "xhsuqzeita43@gmail.com"
```

**Explicación del Código**

El proceso de generación del correo se realiza de la siguiente forma:

- **Parte de Letras**: Se genera una secuencia de 10 caracteres seleccionados aleatoriamente de un conjunto de letras (a-z).
- **Parte de Números**: Se generan 2 dígitos numéricos aleatorios (0-9).
- El resultado final es una concatenación de la parte de letras, la parte numérica y el dominio @gmail.com.

Este tipo de utilidad es fundamental para escenarios de prueba, donde es importante asegurarse de que cada usuario registrado tenga un correo electrónico único.

### Envío de Correos Electrónicos
El proyecto incluye utilidades para la creación y envío de correos electrónicos personalizados, que son fundamentales para la gestión de usuarios en la plataforma **Pensiona-T**. Las funciones permiten enviar correos electrónicos de verificación de cuenta, recuperación de contraseña y mensajes generales a los usuarios.

**Estructura del módulo** `emailUtils`

El archivo `emailUtils.js` contiene tres funciones principales para la generación de correos electrónicos, que son utilizadas para comunicarse con los usuarios de manera automatizada.

#### Funciones en `emailUtils`
1. `createVerificationEmail`:

- Descripción: Crea un correo electrónico para verificar la cuenta de un usuario recién registrado.
- Parámetros:
  - `name`: Nombre del usuario.
  - `email`: Dirección de correo electrónico del usuario.
  - `url`: Enlace de verificación que el usuario debe seguir para activar su cuenta.
- Uso típico: Se utiliza al registrarse un nuevo usuario para enviar un correo de verificación.

**Ejemplo:**

```bash
const { createVerificationEmail } = require('./utils/emailUtils');

const emailContent = createVerificationEmail('Juan Pérez', 'juan.perez@example.com', 'https://example.com/verify');
console.log(emailContent);
```

2. `createRecoveryEmail`:

- **Descripción**: Crea un correo electrónico para la recuperación de contraseña.
- **Parámetros**:
    - `name`: Nombre del usuario.
    - `email`: Dirección de correo electrónico del usuario.
    - `url`: Enlace para restablecer la contraseña.
- **Uso típico**: Se utiliza cuando un usuario solicita la recuperación de su cuenta.
Ejemplo:

```bash
const { createRecoveryEmail } = require('./utils/emailUtils');

const recoveryEmailContent = createRecoveryEmail('Ana Gómez', 'ana.gomez@example.com', 'https://example.com/recover');
console.log(recoveryEmailContent);
```

3. `createGeneralEmail`:

- **Descripción**: Crea un correo electrónico general para enviar mensajes personalizados.
- **Parámetros**:
    - `subject`: Asunto del correo electrónico.
    - `message`: Contenido HTML personalizado del mensaje.
**Uso típico**: Se utiliza para enviar correos electrónicos de comunicación general a los usuarios.

**Ejemplo:**

```bash
const { createGeneralEmail } = require('./utils/emailUtils');

const generalEmailContent = createGeneralEmail('Actualización de la plataforma', '<p>Estimado usuario, hemos realizado actualizaciones importantes...</p>');
console.log(generalEmailContent);
```

### Explicación del Código
El proceso de creación de correos electrónicos se realiza de la siguiente manera:

- **Verificación de cuenta**: Un correo HTML personalizado que incluye el nombre del usuario y un enlace para verificar su cuenta.
- **Recuperación de cuenta**: Un correo HTML personalizado con instrucciones para restablecer la contraseña.
- **Correo general**: Permite enviar correos con contenido personalizado, utilizando un formato HTML básico.

#### Configuración de Correo Electrónico
El envío de correos está configurado para utilizar la dirección `FROM_EMAIL`, definida en el archivo de configuración `config.js`. Esta dirección es la que aparecerá como remitente en todos los correos enviados desde la plataforma **Pensiona-T**.

## Configuración del Proyecto
El proyecto utiliza variables de entorno para configurar parámetros importantes, lo que facilita la adaptación a diferentes entornos (desarrollo, pruebas, producción). Para manejar estas configuraciones, se utiliza el paquete `dotenv`, que carga variables de entorno desde un archivo `.env` en el entorno de ejecución.

### Estructura del módulo `config`
El archivo `config.js` es el encargado de cargar y exportar estas variables de entorno, proporcionando valores clave para la configuración del servidor, la conexión a la base de datos, las claves de autenticación, y otros parámetros esenciales.

### Configuración en `config.js`

1. **Carga de Variables de Entorno:**

- Se utiliza `require('dotenv').config()` para cargar automáticamente las variables de entorno desde un archivo `.env` ubicado en la raíz del proyecto.
- Esto permite mantener la configuración sensible fuera del código fuente, mejorando la seguridad.

2. **Variables de Entorno Utilizadas:**

- `PORT`: El puerto en el que se ejecuta el servidor.
- `MONGODB_URI`: URL de conexión a la base de datos MongoDB.
- `SENDGRID_API_KEY`: API Key para la integración con SendGrid, que se utiliza para el envío de correos electrónicos.
- `FROM_EMAIL`: Dirección de correo electrónico que se utiliza como remitente en los correos electrónicos enviados desde la plataforma.
- `JWT_SECRET`: Clave secreta utilizada para firmar y verificar los tokens JSON Web (JWT).
- `JWT_EXPIRES_IN`: Tiempo de expiración de los JWT utilizados para la autenticación.
- `JWT_REGISTER_EXPIRES_IN`: Tiempo de expiración de los JWT específicamente para la verificación de nuevos registros.
- `JWT_RESET_PASSWORD_EXPIRES_IN`: Tiempo de expiración de los JWT utilizados para la recuperación de contraseñas.
- `URL_FRONTEND`: URL de la aplicación frontend asociada con la plataforma Pensiona-T.

### Ejemplo de Archivo `.env`
A continuación se muestra un ejemplo de cómo debe estructurarse el archivo `.env` para configurar el entorno:

```bash 
# Configuración del servidor
PORT=3000

# Configuración de la base de datos
MONGODB_URI=mongodb://localhost:27017/pensiona-t

# Configuración del correo electrónico y API de SendGrid
SENDGRID_API_KEY=tu_clave_api_de_sendgrid
FROM_EMAIL=noreply@pensiona-t.com

# Configuración del JWT
JWT_SECRET=una_clave_secreta_segura
JWT_EXPIRES_IN=1h
JWT_REGISTER_EXPIRES_IN=24h
JWT_RESET_PASSWORD_EXPIRES_IN=1h

# URL del frontend
URL_FRONTEND=http://localhost:3000
```

### Uso en el Código
En el archivo `config.js`, las variables de entorno se importan y exportan de la siguiente manera:

```bash
require('dotenv').config()

const PORT = process.env.PORT
const MONGODB_URI = process.env.MONGODB_URI
const SENDGRID_API_KEY = process.env.SENDGRID_API_KEY
const FROM_EMAIL = process.env.FROM_EMAIL
const JWT_SECRET = process.env.JWT_SECRET
const JWT_EXPIRES_IN = process.env.JWT_EXPIRES_IN
const JWT_REGISTER_EXPIRES_IN = process.env.JWT_REGISTER_EXPIRES_IN
const JWT_RESET_PASSWORD_EXPIRES_IN = process.env.JWT_RESET_PASSWORD_EXPIRES_IN
const URL_FRONTEND = process.env.URL_FRONTEND

module.exports = {
    MONGODB_URI,
    PORT,
    SENDGRID_API_KEY,
    FROM_EMAIL,
    JWT_SECRET,
    JWT_EXPIRES_IN,
    JWT_REGISTER_EXPIRES_IN,
    JWT_RESET_PASSWORD_EXPIRES_IN,
    URL_FRONTEND
}
```

### Importancia de las Variables de Entorno
El uso de variables de entorno permite:

- **Seguridad**: Mantener la información sensible, como claves API y secretos, fuera del código fuente.
- **Flexibilidad**: Ajustar configuraciones fácilmente para diferentes entornos (desarrollo, producción, pruebas).
- **Escalabilidad**: Permite adaptar la configuración a la infraestructura sin necesidad de cambiar el código fuente.

### Recomendaciones
- Nunca incluyas el archivo .env en el control de versiones. Para evitar esto, asegúrate de agregarlo al archivo .gitignore.

## Modelos de Datos en Mongoose
El proyecto utiliza **Mongoose** para definir y manejar los modelos de datos en la base de datos MongoDB. A continuación, se describen los diferentes esquemas utilizados y sus respectivos campos.

### 1. Modelo `Values`

El modelo `Values` se encarga de almacenar valores relevantes como el **salario mínimo** y la **UMA** (Unidad de Medida y Actualización), utilizados en diferentes cálculos dentro de la aplicación.

#### Esquema `valuesSchema`

```bash
const mongoose = require('mongoose')

const valuesSchema = new mongoose.Schema({
    salarioMinimo: { type: Number, required: true },
    uma: { type: Number, required: true }
})

module.exports = mongoose.model('Values', valuesSchema)
```

#### Descripción de los Campos:
- `salarioMinimo` (`Number`, requerido): Valor del salario mínimo.
- `uma` (`Number`, requerido): Valor de la UMA.

### 2. Modelo `User`
El modelo `User` representa a los usuarios de la aplicación, almacenando información personal, estado de verificación y roles, así como datos sobre el uso de la aplicación.

#### Esquema userSchema

```bash
const mongoose = require('mongoose')

const userSchema = new mongoose.Schema({
    name: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    expiration: { type: Date, required: true },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    created: { type: Date, default: Date.now },
    status: { type: String, enum: ['active', 'inactive'], default: 'active' },
    token: { type: String, default: null },
    verified: { type: Boolean, default: false },
    verificationToken: { type: String, default: null },
    recoveryToken: { type: String, default: null },
    calculosRealizados: { type: Number, default: 0 },
    reportesGenerados: { type: Number, default: 0 },
    aforesConsultadas: { type: Number, default: 0 }
})

module.exports = mongoose.model('User', userSchema)
```

#### Descripción de los Campos:
- name (String, requerido): Nombre del usuario.
- `email` (`String`, requerido, único): Dirección de correo electrónico del usuario.
- `password` (`String`, requerido): Contraseña del usuario.
- expiration (Date, requerido): Fecha de expiración para ciertos permisos o estados.
- `role` (`String`, predeterminado: `user`): Rol del usuario, puede ser `'user'` o `'admin'`.
- created (`Date`, predeterminado: `Date.now`): Fecha de creación del usuario.
- `status` (`String`, predeterminado: `active`): Estado del usuario, puede ser `'active'` o `'inactive'`.
- `token` (`String`, predeterminado: `null`): Token de autenticación del usuario.
- verified (`Boolean`, predeterminado: `false`): Indica si la cuenta está verificada.
- `verificationToken` (`String`, predeterminado: `null`): Token para la verificación del correo electrónico.
- `recoveryToken` (`String`, predeterminado: `null`): Token para la recuperación de contraseña.
- `calculosRealizados` (`Number`, predeterminado: `0`): Cantidad de cálculos realizados por el usuario.
- `reportesGenerados` (`Number`, predeterminado: `0`): Número de reportes generados por el usuario.
- `aforesConsultadas` (`Number`, predeterminado: `0`): Número de AFORES consultadas por el usuario.

### 3. Modelo `LoginHistory`
El modelo `LoginHistory` almacena el historial de inicio de sesión de los usuarios, registrando datos importantes como la fecha de inicio de sesión, la dirección IP y el rol del usuario.

#### Esquema `loginHistorySchema`

```bash
const mongoose = require('mongoose')

const loginHistorySchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
  },
  role: {
    type: String,
    required: true,
  },
  loginDate: {
    type: Date,
    default: Date.now,
  },
  ipAddress: {
    type: String,
  }
})

module.exports = mongoose.model('LoginHistory', loginHistorySchema)
```

#### Descripción de los Campos:
- `email` (`String`, requerido): Dirección de correo electrónico del usuario.
- `role` (`String`, requerido): Rol del usuario en el momento del inicio de sesión.
- `loginDate` (`Date`, predeterminado: `Date.now`): Fecha y hora del inicio de sesión.
- `ipAddress` (`String`): Dirección IP desde la que se inició sesión.

#### Uso de los Modelos
Cada uno de estos modelos se utiliza para interactuar con la base de datos MongoDB. Gracias a Mongoose, se pueden realizar operaciones CRUD (Crear, Leer, Actualizar, Eliminar) de manera sencilla y estructurada. Además, Mongoose permite definir validaciones y restricciones en los esquemas para asegurar la integridad de los datos.

## API para Gestión de Usuarios
Este proyecto proporciona una API para gestionar usuarios con funciones de registro, autenticación, verificación por correo electrónico, recuperación de contraseña, administración y algunas funcionalidades adicionales. A continuación se detallan las rutas disponibles en la API y cómo utilizarlas.

#### Rutas Disponibles

**Redirigir a la URL del Frontend `GET /`**

Redirige a la URL del frontend especificada en la configuración. Útil para navegación en entornos de producción.

---

### Autenticación y Gestión de Sesiones

**Iniciar Sesión `POST /users/api/login`**

Inicia sesión con `email` y `password`. Si el usuario es correcto y la cuenta está verificada, devuelve un token JWT.

**Parámetros en el cuerpo:**

- `email`: Correo electrónico del usuario.
- `password`: Contraseña del usuario.

**Respuesta:**

- `success`: Indica si la operación fue exitosa.
- `email`: Correo electrónico del usuario autenticado.
- `role`: Rol del usuario autenticado.
- `token`: Token de autenticación JWT.

**Cerrar Sesión `POST /users/api/logout`**

Cierra la sesión del usuario autenticado, invalidando el token actual.

---

### Registro y Verificación de Usuario

**Registro de Usuario `POST /users/api/register`**

Registra un nuevo usuario. Envía un correo de verificación al correo proporcionado.

**Parámetros en el cuerpo:**

- `name`: Nombre del usuario.
- `email`: Correo electrónico del usuario.
- `password`: Contraseña del usuario.

**Respuesta:**

- `success`: Indica si la operación fue exitosa.
- `message`: Mensaje indicando el resultado del registro.

**Verificar Cuenta de Usuario `GET /users/api/verify`**

Verifica la cuenta del usuario usando el token enviado por correo electrónico.

**Parámetros en la URL:**

- `token`: Token de verificación enviado por correo.

**Respuesta:**

- `success`: Indica si la operación fue exitosa.
- `message`: Mensaje indicando el resultado de la verificación.

---

### Recuperación de Contraseña

**Solicitar Recuperación de Contraseña ``POST /users/api/recovery``**

Solicita un correo para la recuperación de contraseña. El correo contendrá un token para resetear la contraseña.

**Parámetros en el cuerpo:**

- `email`: Correo electrónico del usuario.

**Respuesta:**

- `success`: Indica si la operación fue exitosa.
- `message`: Mensaje indicando el resultado de la solicitud.

**Validar Token de Recuperación `GET /users/api/recovery`**

Valida el token de recuperación de contraseña.

**Parámetros en la URL:**

- `token`: Token de recuperación.

**Respuesta:**

- `success`: Indica si la operación fue exitosa.
- `message`: Mensaje indicando el resultado de la validación.

**Resetear Contraseña `POST /users/api/reset-password`**

Resetea la contraseña usando el token de recuperación.

**Parámetros en el cuerpo:**

- `token`: Token de recuperación.
- `newPassword`: Nueva contraseña del usuario.

**Respuesta:**

- `success`: Indica si la operación fue exitosa.
- `message`: Mensaje indicando el resultado del reseteo.

---

### Administración (Solo Administradores)

**Obtener Lista de Usuarios `GET /users/api/admin`**

Devuelve una lista de todos los usuarios, excluyendo los administradores. No incluye las contraseñas en la respuesta.

**Respuesta:** Lista de usuarios.

**Crear Usuario `POST /users/api/admin/users`**

Crea un nuevo usuario y envía un correo de verificación.

**Parámetros en el cuerpo:**

- `name`: Nombre del usuario.
- `email`: Correo electrónico del usuario.
- `password`: Contraseña del usuario.
- `role`: Rol del usuario.

**Respuesta:**

- `success`: Indica si la operación fue exitosa.
- `message`: Mensaje indicando el resultado de la creación.

**Actualizar Usuario `PUT /users/api/admin/users/:id`**

Actualiza la información de un usuario específico.

**Parámetros en la URL:**

- `id`: ID del usuario.

**Parámetros en el cuerpo:**

- `name`: Nombre del usuario.
- `email`: Correo electrónico del usuario.
- `role`: Rol del usuario.
- `expiration`: Fecha de expiración.
- `status`: Estado del usuario (activo/inactivo).

**Respuesta:**

- `success`: Indica si la operación fue exitosa.
- `message`: Mensaje indicando el resultado de la actualización.

**Eliminar Usuario `DELETE /users/api/admin/users/:id`**

Elimina un usuario por su ID.

**Parámetros en la URL:**

- `id`: ID del usuario.

**Respuesta:**

- `success`: Indica si la operación fue exitosa.
- `message`: Mensaje indicando el resultado de la eliminación.

**Enviar Correo Masivo `POST /users/api/admin/send-bulk-email`**

Envía un correo masivo a todos los usuarios registrados.

**Parámetros en el cuerpo:**

- `subject`: Asunto del correo.
- `body`: Cuerpo del correo.

**Respuesta:**

- `success`: Indica si la operación fue exitosa.
- `message`: Mensaje indicando el resultado del envío.

---

### Otras Funciones

**Consultar Información de AFORE `POST /users/api/afore-info`**

Realiza una consulta de información de AFORE utilizando un NSS (Número de Seguro Social).

**Parámetros en el cuerpo:**

- `nss`: Número de Seguro Social del usuario.

**Respuesta:** Datos de la AFORE asociada al NSS.

**Obtener Valores (Salario Mínimo, UMA)
`GET /users/api/values`**

Devuelve los valores de salario mínimo y UMA.

**Respuesta:**

- `success`: Indica si la operación fue exitosa.
- `salarioMinimo`: Valor del salario mínimo.
- `uma`: Valor de la UMA.

**Incrementar Contador de Cálculos o Reportes**

`PUT /users/api/user/increment-calculos`

Incrementa el contador de cálculos realizados por el usuario autenticado.

`PUT /users/api/user/increment-reportes`

Incrementa el contador de reportes generados por el usuario autenticado.

## Apoyo
Si tienes preguntas o necesitas soporte, puedes comunicarte a través de:

- Rastreador de problemas en GitHub: Issues
- Correo electrónico: `contacto@pensiona-t.com`

## Hoja de ruta
Aquí hay algunas funcionalidades planificadas para futuras versiones:

- Implementación de refresh tokens.
- Integración con servicios externos de pagos.
- Mejora del sistema de notificaciones.
- Optimización del rendimiento de la API.

## Contribuyendo

¡Las contribuciones son bienvenidas! Si deseas colaborar, sigue estos pasos:

1. Haz un fork del proyecto.
2. Crea una rama para tu funcionalidad (`git checkout -b feature/nueva-funcionalidad`).
3. Realiza los cambios y confirma (`git commit -m 'Añadir nueva funcionalidad'`).
4. Haz un push a la rama (`git push origin feature/nueva-funcionalidad`).
5. Abre un Pull Request en GitHub.

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.

## Estado del proyecto
Actualmente, el proyecto está en fase activa de desarrollo, con actualizaciones y mejoras constantes. Si deseas contribuir, ¡no dudes en contactarnos!
