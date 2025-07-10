<?php

session_start();

if (isset($_SESSION["user_id"])) {
    
    $mysqli = require __DIR__ . "/database.php";
    
    $sql = "SELECT * FROM customers
            WHERE id = {$_SESSION["user_id"]}";
            
    $result = $mysqli->query($sql);
    
    $user = $result->fetch_assoc();
}

?>

<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>About Us | Bonsai</title>

    <link rel="stylesheet" href="https://unpkg.com/swiper@7/swiper-bundle.min.css" />

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">

    <link rel="stylesheet" href="css/style.css">

</head>
<body>
     <!-- HEADER -->
     <header class="header">
        <div id="menu-btn" class="fas fa-bars"></div>

        <a href="index.php" class="logo"> African-Violet <i class="" ></i></a>

        <nav class="navbar">
            <a href="index.php">home</a>
            <a href="about.php">about</a>
            <a href="products.php">products</a>
            <a href="blog.php">Blog</a>
            <a href="research.php">Research</a>
        </nav>
        <?php if (isset($user)): ?>
            <a href="logout.php" class="btn"><?= htmlspecialchars($user["uname"]) ?>, Logout</a>
        
        
    <?php else: ?>
        <a href="login.php" class="btn">Login</a>

        
    <?php endif; ?>
        
     </header>
<!-- REVIEW -->
<section class="team" id="team" style="padding-top: 12rem;">
    <h1 class="heading"><span>Team Members</span></h1>

    <div class="swiper team-slider">
        <div class="swiper-wrapper">
            <div class="swiper-slide box">
                <img src="image/pic-1.jpg" alt="">
                <p>Biraj Acharya Don Ho</p>
                <h3>Biraj Acharya</h3>
                <span>Leader</span>
                <br><span>Hello</span>
            </div>

            <div class="swiper-slide box">
                <img src="image/pic-2.jpg" alt="">
                <p>Biraj Dai Atti Talented</p>
                <h3>Ram Acharya</h3>
                <span>Member</span>
                <br><span>Hello</span>
            </div>

            <div class="swiper-slide box">
                <img src="image/pic-3.jpg" alt="">
                <p>Biraj Dai Hero</p>
                <h3>Shyam Acharya</h3>
                <span>Member</span>
                <br><span>Hello</span>
            </div>

            <div class="swiper-slide box">
                <img src="image/pic-4.jpg" alt="">
                <p>Biraj Dai Tall</p>
                <h3>Hari Acharya</h3>
                <span>Team Member</span>
                <br><span>Hello</span>
            </div>
        </div>
        <div class="swiper-pagination"></div>
    </div>
</section>

        <!-- FOOTER -->
        <section class="footer">
            <div class="box-container">
    
                <div class="box">
                    <h3>quick links</h3>
                    <a href="index.php"><i class="fas fa-arrow-right"></i> home</a>
                    <a href="about.php"><i class="fas fa-arrow-right"></i> about</a>
                    <a href="products.php"><i class="fas fa-arrow-right"></i> Products</a>
                    <a href="blog.php"><i class="fas fa-arrow-right"></i> Blog</a>
                    <a href="research.php"><i class="fas fa-arrow-right"></i> Research</a>
                </div>
    
                <div class="box">
                    <h3>contact info</h3>
                    <a href="#"><i class="fas fa-phone"></i> (+977) 981-234-5678</a>
                    <a href="#"><i class="fas fa-envelope"></i> AfricanViolet@hotmail.com</a>
                    <a href="#"><i class="fas fa-envelope"></i> Chhaimale, Kathmandu</a>
                </div>
    
                <div class="box">
                    <h3>Social Media Sites</h3>
                    <a href="#"><i class="fab fa-facebook-f"></i> facebook</a>
                    
                     <a href="#"><i class="fab fa-instagram"></i> instagram</a>
                    <a href="#"><i class="fab fa-linkedin"></i> linkedin</a>
                    
                </div>
            </div>
    
            <div class="credit">Author <span>Biraj Acharya</span> | all rights reserved 2025</div>
        </section>
    
    <!-- SWIPER -->
    <script src="https://unpkg.com/swiper@7/swiper-bundle.min.js"></script>

    <!-- Custom JS File Link  -->
    <script src="js/script.js"></script>
</body>