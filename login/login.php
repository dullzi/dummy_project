<?php
session_start();
require_once 'koneksi.php';

$maxAttempts = 5;
$lockoutForSeconds = 300;

if (!isset($_SESSION['login_attempts'])) {
    $_SESSION['login_attempts'] = 0;
    $_SESSION['first_attempt_time'] = time();
}

if ($_SESSION['login_attempts'] >= $maxAttempts) {
    $elapsed = time() - ($_SESSION['first_attempt_time'] ?? time());
    if ($elapsed < $lockoutForSeconds) {
        http_response_code(429);
        echo "Too many attempts. Try again Later.";
        exit;
    } else {
        $_SESSION['login_attempts'] = 0;
        $_SESSION['first_attempt_time'] = time();
    }
}
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $username = trim($_POST['username'] ?? '');
    $password = $_POST['password'] ?? '';

    if ($username === '' || $password === '') {
        http_response_code(400);
        echo "Missing Credentials";
        exit;
    }

    if (!preg_match('/^[A-Za-z0-9._]{3,30}$/', $username)) {
        http_response_code(400);
        echo "Invalid username format";
        exit;
    }

    $stmt = mysqli_prepare($koneksi, "SELECT id,name,role,username,password FROM users WHERE username=? LIMIT 1");
    mysqli_stmt_bind_param($stmt, "s", $username);
    mysqli_stmt_execute($stmt);
    mysqli_stmt_bind_result($stmt, $userId, $name, $role, $dbUser, $dbHash);
    mysqli_stmt_fetch($stmt);
    mysqli_stmt_close($stmt);

    $loginSuccess = false;
    if (!empty($dbHash) && password_verify($password, $dbHash)) {
        $loginSuccess = true;
    }

    if ($loginSuccess) {
        $_SESSION['login_attempts'] = 0;
        $_SESSION['first_attempt_time'] = time();

        session_regenerate_id(true);
        $_SESSION['user_id'] = $userId;
        $_SESSION['username'] = $dbUser;

        header("Location: ../homepage/index.html");
        exit;
    } else {
        $_SESSION['login_attempts'] += 1;
        if (!isset($_SESSION['first_attempt_time'])) {
            $_SESSION['first_attempt_time'] = time();
        }

        http_response_code(401);
        echo "Invalid username or password";
        exit;
    }
}

?>

<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <script src="https://cdn.tailwindcss.com"></script>
    <link href="./dist/output.css" rel="stylesheet">
</head>

<body class="min-h-screen items-center flex justify-center bg-gray-200">
    <div class="bg-white border-2 rounded-2xl p-8 shadow-md w-full max-w-sm">
        <div class="flex justify-center mb-6">
            <div class=" h-12 w-12 rounded-full text-white bg-blue-800 items-center flex justify-center">
                PB
            </div>
        </div>

        <h2 class="mb-2 text-2xl font-semibold text-center">Login</h2>
        <p class="text-sm text-gray-600 text-center mb-4">
            Insert enter your username and password
        </p>

        <form action="login.php" method="post" class="space-y-5">
            <div>
                <label for="username" class="w-24 text-sm font-medium block mb-1">Username</label>
                <input class="w-full border-2 text-sm rounded flex-grow p-2 focus:outline-none focus:ring-blue-500 transition" placeholder="Insert your username here.." type="text" name="username" id="username" required pattern="[A-Za-z0-9._]{3,30}" maxlength="30">
            </div>
            <div>
                <label for="password" class="w-24 block text-sm font-medium mb-2">Password</label>
                <input class="border-2 w-full rounded p-2 text-sm flex-grow focus:outline-none focus:ring-blue-500 transition" placeholder="Insert your password here.." type="password" name="password" id="password" required>
            </div>
            <div class="flex mx-auto space-x-2 pt-4 items-center">
                <button type="submit"
                    class="border-2 px-4 bg-blue-800 rounded-lg p-2 hover:bg-blue-600 text-white text-sm transition">Submit</button>
                <a href="register.php" class=" text-sm text-blue-700 hover:underline">Register</a>
            </div>
        </form>
    </div>
</body>

</html>