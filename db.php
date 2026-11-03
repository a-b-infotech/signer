<?php
// db.php
// A B INFOTECH - Database Configuration for License System
$host = 'sql302.ezyro.com';
$dbname = 'ezyro_37092101_fj';
$username = 'ezyro_37092101';
$password = 'abhi@123';

try {
    $pdo = new PDO("mysql:host=$host;dbname=$dbname;charset=utf8mb4", $username, $password, [
        PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
        PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
        PDO::ATTR_TIMEOUT => 5
    ]);
} catch (PDOException $e) {
    try {
        $pdo = new PDO("mysql:host=localhost;dbname=ezyro_37092101_fj;charset=utf8mb4", "root", "", [
            PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
            PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            PDO::ATTR_TIMEOUT => 2
        ]);
    } catch (PDOException $e2) {
        $pdo = null;
    }
}
?>
