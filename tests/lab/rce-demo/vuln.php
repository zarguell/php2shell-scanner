<?php // INTENTIONALLY VULNERABLE LFI sink — lab only, never ship this pattern
$page = $_GET["page"] ?? "index.php";
include($page);
