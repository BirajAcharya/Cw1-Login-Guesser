<?php
session_start();

if ($_SESSION["user_id"] != "admin") {
    header('Location: login_admin.php');
    exit;
}
$mysqli = require __DIR__ . "/database.php";
                                              
?>
<!DOCTYPE html>
<html lang="es">

<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Home | African-Violet</title>

    <link rel="stylesheet" href="https://unpkg.com/swiper@7/swiper-bundle.min.css" />

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/5.15.4/css/all.min.css">

    <link rel="stylesheet" href="css/admin.scss">

    <link rel="stylesheet" href="css/style.css">

</head>

<body>
    <!-- HEADER -->
    <header class="header">
        <div id="menu-btn" class="fas fa-bars"></div>

        <a href="#" class="logo"> Admin Panel <i class=""></i></a>

        <nav class="navbar">
            <a href="">Purchase Orders</a>
        </nav>
        <a href="logout_admin.php" class="btn">Logout</a>


    </header>

    <div style="padding-top: 50px;"></div>
    <div class="container">
  <table class="responsive-table">
    <thead>
      <tr>
        <th >Username</th>
        <th>Product</th>
        <th >Address</th>
        <th >Nearest Landmark</th>
        <th >Email</th>
        <th >Contact</th>
      </tr>
    </thead>
    <tbody>
        <?php
    $sql = "SELECT * FROM orders ORDER BY orders.id DESC";

$result = mysqli_query($mysqli, $sql);
    if(mysqli_num_rows($result) > 0){
        while($row = mysqli_fetch_array($result)){
  ?>
      <tr>
        <th ><?php echo $row['uname']; ?></th>
        <th ><?php echo $row['color']; ?></th>
        <th ><?php echo $row['address']; ?></th>
        <th ><?php echo $row['landmark']; ?></th>
        <th ><?php echo $row['email']; ?></th>
        <th ><?php echo $row['phonenum']; ?></th>
      </tr>
      <?php 
        }
    }
    ?>
    </tbody>
  </table>
</div>
    <!-- FOOTER -->
    <section class="footer">
        <div class="credit">Author <span>Biraj Acharya</span> | all rights reserved 2025</div>




    </section>

    <!-- SWIPER -->
    <script src="https://unpkg.com/swiper@7/swiper-bundle.min.js"></script>

    <!-- Custom JS File Link  -->
    <script src="js/script.js"></script>
</body>

</html>