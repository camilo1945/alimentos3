
    // Función para manejar el clic en el botón "Agregar al Carrito"
document.querySelectorAll('.agregar-carrito').forEach(button => {
    button.addEventListener('click', agregarAlCarrito);
});

function agregarAlCarrito(event) {
    const productoId = event.target.getAttribute('data-producto');
    const precioDolares = parseFloat(event.target.getAttribute('data-precio'));
    
    // Convertir precio a pesos chilenos (1 dólar = X pesos chilenos)
    const precioPesosChilenos = precioDolares * tipoCambioDolarAChile;

    // Crear un elemento de lista para el carrito
    const producto = document.createElement('li');
    producto.textContent = 'Producto ' + productoId + ' - Precio: ' + precioPesosChilenos.toFixed(2) + ' CLP';

    // Agregar el producto al carrito
    document.querySelector('.lista-productos').appendChild(producto);

    // Actualizar el total
    const totalActual = parseFloat(document.querySelector('.total').textContent);
    const nuevoTotal = totalActual + precioPesosChilenos;
    document.querySelector('.total').textContent = nuevoTotal.toFixed(2) + ' CLP';

    // Guardar el carrito en localStorage
    const carrito = JSON.parse(localStorage.getItem('carrito')) || [];
    carrito.push({ productoId, precio: precioPesosChilenos });
    localStorage.setItem('carrito', JSON.stringify(carrito));
}

// Obtener el tipo de cambio del dólar a pesos chilenos
const tipoCambioDolarAChile = 750; // Ejemplo: 1 USD = 750 CLP (solo como ejemplo, debes utilizar el valor actualizado)

// Obtener el botón "Ver Carrito de Compras"
const verCarritoBtn = document.getElementById('ver-carrito');

// Agregar un evento de clic al botón
verCarritoBtn.addEventListener('click', function() {
    // Obtener los productos del carrito del localStorage
    const carrito = JSON.parse(localStorage.getItem('carrito')) || [];

    // Guardar los productos del carrito en el localStorage temporal
    localStorage.setItem('carritoTemp', JSON.stringify(carrito));

    // Redirigir a la página de "Detalle de Pedidos"
    window.location.href = 'Detallepedidos.html';
});

// Función para vaciar el carrito
document.querySelector('.vaciar-carrito').addEventListener('click', function() {
    // Vaciar la lista de productos del carrito en el localStorage
    localStorage.removeItem('carrito');
    // Limpiar la lista de productos en el carrito
    document.querySelector('.lista-productos').innerHTML = '';
    // Reiniciar el total a 0
    document.querySelector('.total').textContent = '0.00 CLP';
});
