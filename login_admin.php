<?php

$is_invalid = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    
    $mysqli = require __DIR__ . "/database.php";
    
    $username = mysqli_real_escape_string($mysqli,strtolower($_POST['uname']));
    $password = mysqli_real_escape_string($mysqli,$_POST['password']);
    
    if($username == "admin" && $password == "admin"){
        session_start();  
        session_regenerate_id(); 
        $_SESSION["user_id"] = "admin";
        header('Location: order-details.php');
    }
    
    $is_invalid = true;
}
?>

<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home | Bonsai</title>

    <!-- SWIPER -->
    <link rel="stylesheet" href="https://unpkg.com/swiper@7/swiper-bundle.min.css" />

    <!-- Font Awesome CDN Link  -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">

    <!-- Custom CSS File Link  -->
    <link rel="stylesheet" href="css/style.css">

</head>
<body>
<!-- HEADER -->

         <!-- HOME -->

    <section class="contact" id="login" >
        <h1 class="heading">Login</h1>
        <?php if ($is_invalid): ?>
        <em>Invalid login</em>
    <?php endif; ?>
        <form method="post" name="adminlogin" onsubmit="form_validate()">
            <input type="text" name="uname" placeholder="Username" class="box">
            <input type="Password" name="password" placeholder="password" class="box">
            <input type="submit" value="Login" class="btn">
        </form>
    </section>
        <!-- FOOTER -->
        <section class="footer">
            <div class="credit">| <a href="index.php"> Back to the Homepage.</a> |</div>
        </section>
    
    <!-- SWIPER -->
    <script src="https://unpkg.com/swiper@7/swiper-bundle.min.js"></script>

    <!-- Custom JS File Link  -->
    <script src="js/script.js"></script>
</body>