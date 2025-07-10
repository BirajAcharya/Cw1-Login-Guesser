<?php

$password_hash = password_hash($_POST["password"], PASSWORD_DEFAULT);

$mysqli = require __DIR__ . "/database.php";

$sql = "INSERT INTO customers (uname, password_hash, email, phonenum, address, landmark)
        VALUES (?, ?, ?,?, ?, ?)";
        
$stmt = $mysqli->stmt_init();

if ( ! $stmt->prepare($sql)) {
    die("SQL error: " . $mysqli->error);
}

$stmt->bind_param("ssssss",
                    $_POST["uname"],
                    $password_hash,
                    $_POST["email"],
                    $_POST["phonenum"],
                    $_POST["address"],
                    $_POST["landmark"]);
                  
if ($stmt->execute()) {
    header("Location: login.php");
    exit;
    
}








