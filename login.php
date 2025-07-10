<?php

$is_invalid = false;

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    
    $mysqli = require __DIR__ . "/database.php";
    
    $sql = sprintf("SELECT * FROM customers
                    WHERE uname = '%s'",
                   $mysqli->real_escape_string($_POST["uname"]));
    
    $result = $mysqli->query($sql);
    
    $user = $result->fetch_assoc();
    
    if ($user) {
        
        if (password_verify($_POST["password"], $user["password_hash"])) {
            
            session_start();
            
            session_regenerate_id();
            
            $_SESSION["user_id"] = $user["id"];
            
            header("Location: index.php");
            exit;
        }
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
        <form method="post" name="loginform" onsubmit="form_validate()">
            <input type="text" name="uname" placeholder="Username" value="<?= htmlspecialchars($_POST["uname"] ?? "") ?>" class="box">
            <input type="Password" name="password" placeholder="password" class="box">
            <input type="submit" value="Login" class="btn">
        </form>
    </section>
        <!-- FOOTER -->
        <section class="footer">
            <div class="credit">Don't have an account? <span><a href="signup.php">Signup</a> </span>| <a href="index.php"> Or Go back to the home page.</a> </div>
        </section>
    
    <!-- SWIPER -->
    <script src="https://unpkg.com/swiper@7/swiper-bundle.min.js"></script>

    <!-- Custom JS File Link  -->
    <script src="js/script.js"></script>
</body>