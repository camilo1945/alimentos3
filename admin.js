document.getElementById("loginForm").addEventListener("submit", function(event) {
    event.preventDefault(); // Evitar que se recargue la página
    
    // Obtener los valores del formulario
    var username = document.getElementById("username").value;
    var password = document.getElementById("password").value;
    
    // Validar el nombre de usuario y la contraseña (por ejemplo, hacer una solicitud AJAX para verificar las credenciales)
    // Aquí puedes agregar tu lógica de autenticación
    
    // Por ahora, simplemente mostraremos un mensaje de éxito si los campos no están vacíos
    if (username && password) {
        alert("Inicio de sesión exitoso para " + username);
    } else {
        alert("Por favor, ingrese un nombre de usuario y una contraseña válidos.");
    }
});
