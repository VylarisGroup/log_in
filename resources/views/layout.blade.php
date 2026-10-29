<!doctype html>
<html lang="de">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="referrer" content="no-referrer">
<title>@yield('title', 'Vylaris log_in')</title>
<style>
:root{--brand:#1867F8;--bg:#f5f7fb;--fg:#14213d;--card:#fff;--muted:#5b6678;--err:#b42318}
@media (prefers-color-scheme:dark){:root{--bg:#0e1420;--fg:#e8edf7;--card:#171f2e;--muted:#9aa6bd;--err:#ff8a80}}
*{box-sizing:border-box}body{margin:0;font:16px/1.5 system-ui,sans-serif;background:var(--bg);color:var(--fg);min-height:100vh;display:grid;place-items:center;padding:16px}
main{width:100%;max-width:400px;background:var(--card);padding:28px;border-radius:12px;box-shadow:0 2px 12px rgba(0,0,0,.08)}
h1{font-size:1.3rem;margin:0 0 16px}label{display:block;margin:12px 0 4px;font-size:.9rem}
input{width:100%;padding:10px;border:1px solid #c5cddb;border-radius:8px;font:inherit;background:transparent;color:inherit}
button{margin-top:18px;width:100%;padding:11px;border:0;border-radius:8px;background:var(--brand);color:#fff;font:inherit;cursor:pointer}
.err{color:var(--err);font-size:.9rem;margin-top:8px}.muted{color:var(--muted);font-size:.85rem}
</style>
</head>
<body><main>@yield('content')</main></body>
</html>
