<?php
// Habilitar la visualización de errores de PHP (solo en entorno de desarrollo)
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

// Conectar a la base de datos
$servername = "localhost:3308";
$username_db = "root";
$password_db = "";
$dbname = "distribucionalimentos";

$conn = new mysqli($servername, $username_db, $password_db, $dbname);

if ($conn->connect_error) {
    die("Conexión fallida: " . $conn->connect_error);
}

// Inicializar el mensaje de error
$loginMessage = "";

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Obtener las credenciales ingresadas por el usuario de manera segura
    $username = isset($_POST['username']) ? $_POST['username'] : '';
    $password = isset($_POST['password']) ? hash('sha256', $_POST['password']) : '';

    if ($username && $password) {
        // Preparar la consulta para evitar inyecciones SQL
        $stmt = $conn->prepare("SELECT * FROM administradores WHERE username = ? AND hashed_password = ?");
        $stmt->bind_param("ss", $username, $password);

        // Ejecutar la consulta
        $stmt->execute();
        $result = $stmt->get_result();

        if ($result->num_rows > 0) {
            header("Location: index_admin.html");
            exit();
        } else {
            $loginMessage = "Nombre de usuario o contraseña incorrectos.";
        }

        // Cerrar la declaración
        $stmt->close();
    } else {
        $loginMessage = "Por favor, ingrese tanto el nombre de usuario como la contraseña.";
    }
}

// Cerrar la conexión
$conn->close();
?>