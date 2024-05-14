// inventario.js

const searchInput = document.getElementById('searchInput');
const table = document.getElementById('productTable').getElementsByTagName('tbody')[0];

// Hacer una solicitud GET al servidor para obtener los productos
fetch('http://localhost:3004/productos')
    .then(response => response.json())
    .then(data => {
        // Iterar sobre los productos recibidos y crear las filas de la tabla
        data.forEach(producto => {
            const row = document.createElement('tr');
            row.innerHTML = `
                <td>${producto.id}</td>
                <td>${producto.nombre}</td>
                <td>${producto.descripcion}</td>
                <td>${producto.precio}</td>
                <td>${producto.stock}</td>
            `;
            table.appendChild(row);
        });
    })
    .catch(error => {
        console.error('Error al obtener los productos:', error);
    });

// Agregar evento de búsqueda
searchInput.addEventListener('keyup', function() {
    const searchText = searchInput.value.trim().toLowerCase();
    const rows = table.getElementsByTagName('tr');
    for (let i = 0; i < rows.length; i++) {
        const name = rows[i].getElementsByTagName('td')[1].innerText.trim().toLowerCase();
        if (name.includes(searchText)) {
            rows[i].style.display = '';
        } else {
            rows[i].style.display = 'none';
        }
    }
});


