/* 
 * Click nbfs://nbhost/SystemFileSystem/Templates/Licenses/license-default.txt to change this license
 * Click nbfs://nbhost/SystemFileSystem/Templates/ClientSide/javascript.js to edit this template
 */

// Esta función se ejecuta cuando la ventana y el DOM se han cargado completamente
window.onload = function() {
    obtenerProductos(); // Llama a la función para cargar la lista de productos
};

// Esta función se ejecuta cuando el DOM se ha cargado completamente
document.addEventListener('DOMContentLoaded', function() {
    const formulario = document.getElementById('formularioProductos');
    const mensaje = document.getElementById('mensaje');

    formulario.addEventListener('submit', function(event) {
        event.preventDefault(); // Evitar el envío del formulario por defecto

        // Aquí podrías agregar la lógica para enviar los datos del formulario al servidor

        // Mostrar el mensaje de éxito
        mensaje.textContent = 'Producto guardado exitosamente';
        mensaje.style.backgroundColor = 'lightgreen'; 

        console.log('Formulario enviado'); // Verifica si este mensaje se muestra en la consola
    });
});

// Esta función se ejecuta cuando se hace clic en el botón "Consultar Productos"
function consultarProductos() {
    // Aquí puedes escribir el código para consultar los productos
    alert("Se ha hecho clic en el botón 'Consultar Productos'");
}


// Función para obtener y mostrar la lista de productos
function obtenerProductos() {
    fetch('/api/productos')
        .then(response => response.json())
        .then(data => {
            const productosContainer = document.getElementById('productosContainer');
            productosContainer.innerHTML = '';
            data.forEach(producto => {
                const productoElement = document.createElement('div');
                productoElement.textContent = `${producto.id} - ${producto.nombre} - ${producto.precio}`;
                productosContainer.appendChild(productoElement);
            });
        })
        .catch(error => {
            console.error('Error al obtener productos:', error);
        });
}

function guardarProducto() {
    const nombre = document.getElementById('nombre').value;
    const descripcion = document.getElementById('descripcion').value;
    const precio = parseFloat(document.getElementById('precio').value);
    const stock = parseInt(document.getElementById('stock').value);

    const producto = { nombre, descripcion, precio, stock };

    fetch('/api/productos', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify(producto)
    })
    .then(response => {
        if (response.ok) {
            document.getElementById('mensaje').textContent = 'Producto guardado exitosamente';
            obtenerProductos(); // Actualizar la lista de productos
        } else {
            throw new Error('Error al guardar el producto');
        }
    })
    .catch(error => {
        console.error('Error al guardar el producto:', error);
        document.getElementById('mensaje').textContent = 'Error al guardar el producto';
    });
}

// Obtener los productos al cargar la página
window.onload = obtenerProductos;
