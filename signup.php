<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home | African-Violet</title>

    <!-- SWIPER -->
    <link rel="stylesheet" href="https://unpkg.com/swiper@7/swiper-bundle.min.css" />

    <!-- Font Awesome CDN Link  -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">

    <!-- Custom CSS File Link  -->
    <link rel="stylesheet" href="css/style.css">

</head>
<body>

         <!-- HOME -->

    <section class="contact" id="signup" >
        <h1 class="heading">Create an account</h1>

        <form action="process-signup.php" method="post" name="signupform" onsubmit="form_validate()">
            <input type="text" name="uname" placeholder="Create Username" class="box">
            <input type="Password" name="password" placeholder="Create password" class="box">
            <input type="email" name="email" placeholder="Enter email address" class="box">
            <input type="text" name="phonenum" placeholder="Enter your Mobile number." class="box">
            <input type="text" name="address" placeholder="Enter your address." class="box">
            <input type="text" name="landmark" placeholder="Nearest landmark." class="box">
            <input type="submit" value="Signup" class="btn">
        </form>
    </section>
        <!-- FOOTER -->
        <section class="footer">
            <div class="credit">Already have an account? <span><a href="login.php">Login!</a></span>| <a href="index.php"> Or return to the website.</a> </div>
        </section>
    
    <!-- SWIPER -->
    <script src="https://unpkg.com/swiper@7/swiper-bundle.min.js"></script>

    <!-- Custom JS File Link  -->
    <script src="js/script.js"></script>
</body>