# Pensiona-T Back-End

Bienvenido al repositorio de Pensiona-T Back-End. Este proyecto se encarga de gestionar la lógica del servidor y las interacciones con la base de datos para la aplicación Pensiona-T.

## Tabla de Contenidos

- [Introducción](#introducción)
- [Características](#características)
- [Instalación](#instalación)
- [Uso](#uso)
- [Contribución](#contribución)
- [Licencia](#licencia)

## Introducción

Pensiona-T Back-End está construido con tecnologías web modernas para garantizar escalabilidad, seguridad y rendimiento. Proporciona APIs RESTful para la aplicación front-end y maneja toda la lógica de negocio y la persistencia de datos.

## Características

- Autenticación y autorización de usuarios
- Arquitectura segura y escalable

## Instalación

Para comenzar con Pensiona-T Back-End, sigue estos pasos:

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
    npm install
    ```
4. Configura las variables de entorno creando un archivo `.env` 
    ```bash
    MONGODB_URI=TU_URL
    JWT_SECRET=TU_FRASE_SECRETA
    PORT=5000
    SENDGRID_API_KEY='TU_API_KEY'
    FROM_EMAIL=tuemail@gmail.com
    URL_FRONTEND=https://tuurl.com
    ```
5. Ejecuta la aplicación:
    ```bash
    npm start
    ```

## Uso

Después de la instalación, el servidor back-end estará funcionando en `http://localhost:5000`. Puedes usar herramientas como Postman para interactuar con las APIs.

## Contribución

Damos la bienvenida a contribuciones al proyecto Pensiona-T Back-End. Para contribuir, sigue estos pasos:

1. Haz un fork del repositorio.
2. Crea una nueva rama:
    ```bash
    git checkout -b nombre-de-la-funcionalidad
    ```
3. Realiza tus cambios y haz commit:
    ```bash
    git commit -m "Descripción de los cambios"
    ```
4. Haz push a la rama:
    ```bash
    git push origin nombre-de-la-funcionalidad
    ```
5. Crea un pull request.

## Licencia

Este proyecto está licenciado bajo la Licencia MIT. Consulta el archivo [LICENSE](LICENSE) para más detalles.
