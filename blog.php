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
    <title>Blog | African-Violet</title>

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
            <a href="product.php">products</a>
            <a href="blog.php">Blog</a>
            <a href="research.php">Research</a>
        </nav>
        <?php if (isset($user)): ?>
            <a href="logout.php" class="btn"><?= htmlspecialchars($user["uname"]) ?>, Logout</a>
        
        
    <?php else: ?>
        <a href="login.php" class="btn">Login</a>

        
    <?php endif; ?>
        
     </header>
    <!-- ABOUT -->
    <section class="about" id="about" style="padding-top: 18rem">
      <h1 class="heading">
        <span>how technology has affected daily life and business</span>
      </h1>

      <div class="row">
        <div class="content" style="padding-top: 8rem">
          <h3 class="title">Placeholder Heading</h3>
          <p>
          The African violet (*Saintpaulia*) is a small, flowering houseplant native to East Africa, particularly Tanzania and Kenya. It is cherished for its vibrant blooms, which come in shades of purple, pink, blue, white, or bi-colored varieties, and its fuzzy, dark green leaves that grow in a rosette pattern. Typically reaching 6–12 inches in width and height, African violets can bloom year-round indoors when given proper care. They thrive in bright, indirect light and prefer well-draining, lightweight soil that is kept consistently moist but not soggy. Watering should be done with room-temperature water, avoiding the leaves to prevent spotting. These plants also enjoy moderate to high humidity and temperatures between 65–75°F (18–24°C). Regular feeding with a balanced, water-soluble fertilizer encourages healthy growth and continuous blooming. However, they can be susceptible to issues such as root rot from overwatering, drooping from underwatering, powdery mildew in humid environments with poor airflow, and pests like spider mites and mealybugs. Despite these potential challenges, African violets remain a favorite among houseplant enthusiasts due to their beauty, compact size, and relatively easy care requirements.
          </p>
          <h3 class="title">Placeholder Heading</h3>
          <p>
          The African violet (*Saintpaulia*) is a small, flowering houseplant native to East Africa, particularly Tanzania and Kenya. It is cherished for its vibrant blooms, which come in shades of purple, pink, blue, white, or bi-colored varieties, and its fuzzy, dark green leaves that grow in a rosette pattern. Typically reaching 6–12 inches in width and height, African violets can bloom year-round indoors when given proper care. They thrive in bright, indirect light and prefer well-draining, lightweight soil that is kept consistently moist but not soggy. Watering should be done with room-temperature water, avoiding the leaves to prevent spotting. These plants also enjoy moderate to high humidity and temperatures between 65–75°F (18–24°C). Regular feeding with a balanced, water-soluble fertilizer encourages healthy growth and continuous blooming. However, they can be susceptible to issues such as root rot from overwatering, drooping from underwatering, powdery mildew in humid environments with poor airflow, and pests like spider mites and mealybugs. Despite these potential challenges, African violets remain a favorite among houseplant enthusiasts due to their beauty, compact size, and relatively easy care requirements.
          </p>
          <h3 class="title">Placeholder Heading</h3>
          <p>
          The African violet (*Saintpaulia*) is a small, flowering houseplant native to East Africa, particularly Tanzania and Kenya. It is cherished for its vibrant blooms, which come in shades of purple, pink, blue, white, or bi-colored varieties, and its fuzzy, dark green leaves that grow in a rosette pattern. Typically reaching 6–12 inches in width and height, African violets can bloom year-round indoors when given proper care. They thrive in bright, indirect light and prefer well-draining, lightweight soil that is kept consistently moist but not soggy. Watering should be done with room-temperature water, avoiding the leaves to prevent spotting. These plants also enjoy moderate to high humidity and temperatures between 65–75°F (18–24°C). Regular feeding with a balanced, water-soluble fertilizer encourages healthy growth and continuous blooming. However, they can be susceptible to issues such as root rot from overwatering, drooping from underwatering, powdery mildew in humid environments with poor airflow, and pests like spider mites and mealybugs. Despite these potential challenges, African violets remain a favorite among houseplant enthusiasts due to their beauty, compact size, and relatively easy care requirements.
          </p>

          <h3 class="title">Placeholder Heading</h3>
          <p>
          The African violet (*Saintpaulia*) is a small, flowering houseplant native to East Africa, particularly Tanzania and Kenya. It is cherished for its vibrant blooms, which come in shades of purple, pink, blue, white, or bi-colored varieties, and its fuzzy, dark green leaves that grow in a rosette pattern. Typically reaching 6–12 inches in width and height, African violets can bloom year-round indoors when given proper care. They thrive in bright, indirect light and prefer well-draining, lightweight soil that is kept consistently moist but not soggy. Watering should be done with room-temperature water, avoiding the leaves to prevent spotting. These plants also enjoy moderate to high humidity and temperatures between 65–75°F (18–24°C). Regular feeding with a balanced, water-soluble fertilizer encourages healthy growth and continuous blooming. However, they can be susceptible to issues such as root rot from overwatering, drooping from underwatering, powdery mildew in humid environments with poor airflow, and pests like spider mites and mealybugs. Despite these potential challenges, African violets remain a favorite among houseplant enthusiasts due to their beauty, compact size, and relatively easy care requirements.
          </p>
          <h3 class="title">Placeholder Heading</h3>
          <p>
          The African violet (*Saintpaulia*) is a small, flowering houseplant native to East Africa, particularly Tanzania and Kenya. It is cherished for its vibrant blooms, which come in shades of purple, pink, blue, white, or bi-colored varieties, and its fuzzy, dark green leaves that grow in a rosette pattern. Typically reaching 6–12 inches in width and height, African violets can bloom year-round indoors when given proper care. They thrive in bright, indirect light and prefer well-draining, lightweight soil that is kept consistently moist but not soggy. Watering should be done with room-temperature water, avoiding the leaves to prevent spotting. These plants also enjoy moderate to high humidity and temperatures between 65–75°F (18–24°C). Regular feeding with a balanced, water-soluble fertilizer encourages healthy growth and continuous blooming. However, they can be susceptible to issues such as root rot from overwatering, drooping from underwatering, powdery mildew in humid environments with poor airflow, and pests like spider mites and mealybugs. Despite these potential challenges, African violets remain a favorite among houseplant enthusiasts due to their beauty, compact size, and relatively easy care requirements.
        </div>
      </div>
    </section>
    <!-- FOOTER -->
    <section class="footer">
      <div class="box-container">
        <div class="box">
          <h3>quick links</h3>
          <a href="index.php"><i class="fas fa-arrow-right"></i> Home</a>
          <a href="about.php"><i class="fas fa-arrow-right"></i> About</a>
          <a href="products.php"
            ><i class="fas fa-arrow-right"></i> Products</a
          >
          <a href="blog.php"><i class="fas fa-arrow-right"></i> Blog</a>
          <a href="research.php"
            ><i class="fas fa-arrow-right"></i> Research</a
          >
        </div>

        <div class="box">
          <h3>contact info</h3>
          <a href="#"><i class="fas fa-phone"></i> 9843567896</a>
          <a href="#"><i class="fas fa-envelope"></i> AfricanViolet@hotmail.com</a>
          <a href="#"><i class="fas fa-envelope"></i> Chhaimale,Kathmandu</a>
        </div>

        <div class="box">
          <h3>Social Media</h3>
          <a href="#"><i class="fab fa-facebook-f"></i> facebook</a>
          
          <a href="#"><i class="fab fa-instagram"></i> instagram</a>
          <a href="#"><i class="fab fa-linkedin"></i> linkedin</a>
         
        </div>
      </div>

      <div class="credit">
        Author <span>Biraj Acharya</span> | all rights reserved 2025
      </div>
    </section>

    <!-- SWIPER -->
    <script src="https://unpkg.com/swiper@7/swiper-bundle.min.js"></script>

    <!-- Custom JS File Link  -->
    <script src="js/script.js"></script>
  </body>
</html>
