
    // Función para obtener los productos del carrito almacenados en el localStorage
    function obtenerProductosDelCarrito() {
        const productos = localStorage.getItem('carrito');
        return productos ? JSON.parse(productos) : [];
    }

    // Función para mostrar los productos en el detalle de pedidos
    function mostrarProductosEnDetalle() {
        const productos = obtenerProductosDelCarrito();
        const listaPedidos = document.querySelector('.lista-pedidos');
        listaPedidos.innerHTML = '';

        // Mostrar cada producto en la lista de pedidos
        let total = 0;
        productos.forEach(producto => {
            const itemPedido = document.createElement('li');
            itemPedido.textContent = 'Producto: ' + producto.productoId + ' - Precio: ' + producto.precio.toFixed(2) + ' CLP';
            listaPedidos.appendChild(itemPedido);
            total += producto.precio;
        });

        // Actualizar el total
        document.querySelector('.total').textContent = total.toFixed(2);
    }

    // Mostrar los productos en el detalle de pedidos al cargar la página
    mostrarProductosEnDetalle();

    // Obtener el botón "Volver a Productos"
    const volverProductosBtn = document.getElementById('volver-productos');

    // Agregar un evento de clic al botón
    volverProductosBtn.addEventListener('click', function() {
        // Recuperar los productos del carrito temporal del localStorage
        const carritoTemp = JSON.parse(localStorage.getItem('carritoTemp')) || [];

        // Guardar los productos del carrito temporal en el carrito principal del localStorage
        localStorage.setItem('carrito', JSON.stringify(carritoTemp));

        // Redirigir a la página de "Productos Clientes"
        window.location.href = 'Productos_clientes.html';
    });

    // Función para vaciar el carrito temporal
    function vaciarCarritoTemporal() {
        // Vaciar la lista de productos del carrito temporal en el localStorage
        localStorage.removeItem('carritoTemp');
    }


