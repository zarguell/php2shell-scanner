// SPA bundle: all API routes live here, NOT in index.html (no .php in HTML).
const API = "/api/v2/endpoint.php";
fetch("/api/v2/endpoint.php?action=status").then(r => r.json());
import("/portal/deep.php");
