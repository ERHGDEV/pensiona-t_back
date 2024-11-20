const generarEmailAleatorio = () => {
    const letras = 'abcdefghijklmnopqrstuvwxyz'
    const numeros = '0123456789'
  
    const parteLetras = Array.from({ length: 10 }, () =>
      letras.charAt(Math.floor(Math.random() * letras.length))
    ).join('')
  
    const parteNumeros = Array.from({ length: 2 }, () =>
      numeros.charAt(Math.floor(Math.random() * numeros.length))
    ).join('')
  
    return `${parteLetras}${parteNumeros}@gmail.com`
}

module.exports = {
    generarEmailAleatorio
}