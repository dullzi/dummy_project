<?php
session_start();
require_once 'koneksi.php'; // $koneksi sudah konek ke DB

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';
    $name     = trim($_POST['name'] ?? '');
    $role     = $_POST['role'] ?? 'user'; // default user, bisa 'admin'

    // Validasi basic
    if ($username === '' || $password === '' || $name === '') {
        echo "Semua field wajib diisi!";
        exit;
    }

    if (!preg_match('/^[A-Za-z0-9._]{3,30}$/', $username)) {
        echo "Username hanya boleh huruf, angka, dot, underscore (3-30 char)";
        exit;
    }

    // Cek username sudah ada
    $stmt = mysqli_prepare($koneksi, "SELECT id FROM users WHERE username=? LIMIT 1");
    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_store_result($stmt);
    if (mysqli_stmt_num_rows($stmt) > 0) {
        echo "Username sudah digunakan!";
        mysqli_stmt_close($stmt);
        exit;
    }
    mysqli_stmt_close($stmt);

    // Hash password
    $hashedPassword = password_hash($password, PASSWORD_DEFAULT);

    // Insert user baru
    $stmt = mysqli_prepare($koneksi, "INSERT INTO users (name, role, username, password) VALUES (?, ?, ?, ?)");
    mysqli_stmt_bind_param($stmt, "ssss", $name, $role, $username, $hashedPassword);
    if (mysqli_stmt_execute($stmt)) {
        echo "Akun berhasil dibuat! Username: $username, Role: $role";
    } else {
        echo "Gagal membuat akun: " . mysqli_error($koneksi);
    }
    mysqli_stmt_close($stmt);
    exit;
}
?>

<!DOCTYPE html>
<html lang="id">

<head>
    <meta charset="UTF-8">
    <title>Register</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="./dist/output.css" rel="stylesheet">
</head>

<body class="min-h-screen bg-gray-200 items-center justify-center flex">
    <div class="bg-white p-8 shadow-md w-full max-w-sm rounded-lg">
        <div class="flex justify-center mb-6">
            <div class=" h-12 w-12 rounded-full text-white bg-blue-800 items-center flex justify-center">
                PB
            </div>
        </div>

        <h2 class="font-semibold text-2xl text-center mb-2">Create Account</h2>
        <p class="mb-4 text-center text-sm text-gray-600">Register to access the dashboard</p>

        <form method="post" action="register.php" class="space-y-4">
            <div>
                <label class="w-24 text-sm font-medium block mb-1" for="name">Nama:</label>
                <input type="text" name="name" required maxlength="50" class="w-full p-2 border rounded-lg focus:ring-blue-500 focus:outline-none transition" placeholder="Insert your name here..">
            </div>
            <div>
                <label class="w-24 text-sm font-medium block mb-1" for="username">Username:</label>
                <input class="w-full p-2 border rounded-lg focus:outline-none focus:ring-blue-500 transition" placeholder="Insert your username here.." type="text" name="username" required pattern="[A-Za-z0-9._]{3,30}" maxlength="30">
            </div>
            <div>
                <label for="password" class="w-24 text-sm font-medium block mb-1">Password:</label>
                <input class="w-full p-2 border rounded-lg focus:outline-none focus:ring-blue-500 transition" placeholder="Insert your password here.." type="password" name="password" required>
            </div>
            <div>
                <label>Role:</label>
                <select name="role" class="w-full border-2 p-1 focus:ring-2 focus:outline-none focus:ring-blue-500 transition rounded-lg">
                    <option value="user">User</option>
                    <option value="admin">Admin</option>
                </select>
            </div>

            <div class="flex items-center pt-4 justify-center">
                <button type="submit" class="py-2 w-full bg-blue-800 text-white rounded-lg border hover:bg-blue-600 transition text-sm">Register</button>
            </div>

            <div class="text-center">
                <p class="text-sm text-gray-600 ">Already have account?<a href="login.php" class="text-blue-800 text-sm hover:underline"> Login</a></p>
            </div>
        </form>
    </div>
</body>

</html>