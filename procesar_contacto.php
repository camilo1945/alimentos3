<?php
if ($_SERVER["REQUEST_METHOD"] == "POST") {
    // Obtener los datos del formulario
    $nombre = $_POST["nombre"];
    $email = $_POST["email"];
    $mensaje = $_POST["mensaje"];

    // Correo de destino
    $destinatario = "tucorreo@example.com";

    // Asunto del correo
    $asunto = "Nuevo mensaje de contacto desde tu sitio web";

    // Construir el cuerpo del correo
    $cuerpoMensaje = "Nombre: $nombre\n";
    $cuerpoMensaje .= "Correo electrónico: $email\n";
    $cuerpoMensaje .= "Mensaje:\n$mensaje";

    // Encabezados del correo
    $headers = "From: $nombre <$email>\r\n";
    $headers .= "Reply-To: $email\r\n";

    // Enviar el correo
    if (mail($destinatario, $asunto, $cuerpoMensaje, $headers)) {
        // Correo enviado con éxito
        echo "<p>¡Gracias por tu mensaje! Nos pondremos en contacto contigo pronto.</p>";
    } else {
        // Error al enviar el correo
        echo "<p>Hubo un error al enviar tu mensaje. Por favor, inténtalo de nuevo más tarde.</p>";
    }
} else {
    // Acceso no válido al script
    echo "<p>Error: Acceso no válido.</p>";
}
?>
}
