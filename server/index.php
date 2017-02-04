<?php

if ($_GET['data'] == 'abcdefghijklmnopqrstuvwxyz') {
    echo 'Exploit SUCCESS';
} else {
    echo "<h1>Test page</h1>\n";
    echo "<pre>";
    print_r($_GET);
    echo "</pre>";
}

?>
