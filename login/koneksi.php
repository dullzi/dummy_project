<?php

$host = "localhost";
$user = "root";
$pass = "";
$db = "peminjaman_buku";

$koneksi = mysqli_connect($host,$user,$pass,$db);

if(!$koneksi) {
    die ("Error connect to database: ".mysqli_connect_error());
}
?>