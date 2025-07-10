<?php
$is_invalid = false;
session_start();

if (!isset($_SESSION["user_id"])) {

    header("Location: login.php");
    exit;
}

if (isset($_SESSION["user_id"])) {
    
    $mysqli = require __DIR__ . "/database.php";
    
    $sql = "SELECT * FROM customers
            WHERE id = {$_SESSION["user_id"]}";
            
    $result = $mysqli->query($sql);
    
    $user = $result->fetch_assoc();


    $sql = "INSERT INTO orders (uname, color, email, phonenum, address, landmark)
    VALUES (?, ?, ?, ?, ?, ?)";
    
    $stmt = $mysqli->stmt_init();

    if ( ! $stmt->prepare($sql)) {
    die("SQL error: " . $mysqli->error);
    }

    $stmt->bind_param("ssssss",
                $user["uname"],
                $_POST["color"],
                $user["email"],
                $user["phonenum"],
                $user["address"],
                $user["landmark"]);
              
    if ($stmt->execute()) {
    header("Location: products.php");
    exit;

    }

    $is_invalid = true;

}

?>









