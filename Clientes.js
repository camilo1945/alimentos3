
        // Función para hacer una solicitud GET al servidor para obtener los clientes filtrados por nombre
        function filtrarClientesPorNombre() {
            const searchText = searchInput.value.trim();
            fetch(`http://localhost:3002/clientes?nombre=${searchText}`)
                .then(response => response.json())
                .then(data => {
                    // Limpiar la tabla antes de agregar nuevos datos
                    const tableBody = document.getElementById('clientesBody');
                    tableBody.innerHTML = '';
                    // Iterar sobre los datos de los clientes y agregar filas a la tabla
                    data.forEach(cliente => {
                        const row = document.createElement('tr');
                        row.innerHTML = `
                            <td>${cliente.id}</td>
                            <td>${cliente.nombre}</td>
                            <td>${cliente.direccion}</td>
                            <td>${cliente.correo}</td>
                            <td>${cliente.telefono || '-'}</td>
                        `;
                        tableBody.appendChild(row);
                    });
                })
                .catch(error => {
                    console.error('Error al obtener los clientes:', error);
                });
        }

        // Agregar evento de búsqueda al campo de entrada
        const searchInput = document.getElementById('searchInput');
        searchInput.addEventListener('keyup', filtrarClientesPorNombre);
