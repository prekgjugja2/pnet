<?php
declare(strict_types=1);

require __DIR__ . '/lib/app.php';

pnet_session();
pnet_security_headers();

try {
    $pdo = pnet_boot();
} catch (RuntimeException $e) {
    pnet_fail_page($e->getMessage());
} catch (Throwable $e) {
    pnet_fail_page('PNet could not start its database.');
}

if (!pnet_on_home_network()) {
    pnet_fail_page('Connect to this home Wi-Fi, then open PNet again. Every page is available from devices on that network. No account is required.', 'Home Wi‑Fi only');
}

$boot = json_encode([
    'csrf' => pnet_csrf(),
], JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT);
pnet_begin('PNet');
?>
<div class="app">
    <aside class="side">
        <div class="brand">
            <img src="assets/favicon.svg" alt="" width="32" height="32">
            <div>
                <strong>PNet</strong>
                <p id="home-name">Home network</p>
            </div>
        </div>
        <nav class="nav">
            <a href="#overview"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 11.5 12 4l9 7.5"/><path d="M6 10.5V20h12v-9.5"/></svg></span>Overview</a>
            <a href="#wifi"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M5 12.5a9 9 0 0 1 14 0"/><path d="M8.5 15.5a5 5 0 0 1 7 0"/><circle cx="12" cy="19" r="1.2" fill="currentColor" stroke="none"/></svg></span>Router</a>
            <a href="#network"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="4" width="7" height="7" rx="1.5"/><rect x="14" y="4" width="7" height="7" rx="1.5"/><rect x="8.5" y="13" width="7" height="7" rx="1.5"/><path d="M6.5 11v2.5h4M17.5 11v2.5h-4"/></svg></span>Devices</a>
            <a href="#traffic"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 20V10"/><path d="M9 20V4"/><path d="M15 20v-8"/><path d="M21 20V8"/></svg></span>Traffic</a>
            <a href="#firewall"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3 5 6v5c0 5 3.2 8.2 7 9.5 3.8-1.3 7-4.5 7-9.5V6l-7-3z"/></svg></span>Firewall</a>
            <a href="#sites"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="9"/><path d="M4.5 9.5h15M4.5 14.5h15"/><path d="M12 3c2.5 2.8 3.8 5.8 3.8 9S14.5 18.2 12 21c-2.5-2.8-3.8-5.8-3.8-9S9.5 5.8 12 3z"/><path d="M7 7l10 10"/></svg></span>Blocking</a>
            <a href="#ips"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M8 7h11M8 12h11M8 17h11"/><circle cx="4.5" cy="7" r="1.2" fill="currentColor" stroke="none"/><circle cx="4.5" cy="12" r="1.2" fill="currentColor" stroke="none"/><circle cx="4.5" cy="17" r="1.2" fill="currentColor" stroke="none"/></svg></span>IP list</a>
            <a href="#defender"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 21a9 9 0 1 0-9-9"/><path d="M12 7v5l3 2"/><path d="M3 16l2.5 2.5L9 15"/></svg></span>Defender</a>
            <a href="#cameras"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 8.5h11a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-8.5z"/><path d="M16 11.5 21 9v8l-5-2.5"/><circle cx="8.5" cy="13.5" r="1.8"/></svg></span>Cameras</a>
            <a href="#settings"><span class="nav-icon" aria-hidden="true"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><circle cx="12" cy="12" r="3"/><path d="M19.4 15a1.7 1.7 0 0 0 .3 1.8l.1.1a2 2 0 1 1-2.8 2.8l-.1-.1a1.7 1.7 0 0 0-1.8-.3 1.7 1.7 0 0 0-1 1.5V21a2 2 0 1 1-4 0v-.1a1.7 1.7 0 0 0-1-1.5 1.7 1.7 0 0 0-1.8.3l-.1.1a2 2 0 1 1-2.8-2.8l.1-.1a1.7 1.7 0 0 0 .3-1.8 1.7 1.7 0 0 0-1.5-1H3a2 2 0 1 1 0-4h.1a1.7 1.7 0 0 0 1.5-1 1.7 1.7 0 0 0-.3-1.8l-.1-.1a2 2 0 1 1 2.8-2.8l.1.1a1.7 1.7 0 0 0 1.8.3H9a1.7 1.7 0 0 0 1-1.5V3a2 2 0 1 1 4 0v.1a1.7 1.7 0 0 0 1 1.5 1.7 1.7 0 0 0 1.8-.3l.1-.1a2 2 0 1 1 2.8 2.8l-.1.1a1.7 1.7 0 0 0-.3 1.8V9a1.7 1.7 0 0 0 1.5 1H21a2 2 0 1 1 0 4h-.1a1.7 1.7 0 0 0-1.5 1z"/></svg></span>Settings</a>
        </nav>
        <div class="side-foot">
            <p class="who">Open on this Wi‑Fi</p>
        </div>
    </aside>
    <div class="workspace">
        <header class="top">
            <div>
                <p class="eyebrow" id="eyebrow">Home console</p>
                <h1 id="title">Overview</h1>
            </div>
            <div class="top-actions" id="actions"></div>
        </header>
        <div id="main"><p class="lead">Loading your network…</p></div>
    </div>
</div>
<div id="drawer" class="drawer-back" hidden></div>
<div id="toasts"></div>
<script id="pnet-boot" type="application/json"><?php echo $boot; ?></script>
<script src="assets/app.js"></script>
<?php
pnet_end();

function pnet_fail_page(string $message, string $title = 'PNet needs a fix'): void
{
    pnet_security_headers();
    pnet_begin('PNet');
    echo '<main class="gate"><section class="gate-card"><h2>' . pnet_h($title) . '</h2><p class="error">' . pnet_h($message) . '</p></section></main>';
    pnet_end();
    exit;
}

function pnet_begin(string $title): void
{
    header('Content-Type: text/html; charset=utf-8');
    echo '<!DOCTYPE html><html lang="en"><head><meta charset="utf-8">';
    echo '<meta name="viewport" content="width=device-width, initial-scale=1">';
    echo '<meta name="robots" content="noindex">';
    echo '<meta name="theme-color" content="#14120f">';
    echo '<title>' . pnet_h($title) . '</title>';
    echo '<link rel="icon" href="assets/favicon.svg">';
    echo '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?family=Plus+Jakarta+Sans:wght@400;500;600;700&family=IBM+Plex+Mono:wght@400;500;600&display=swap">';
    echo '<link rel="stylesheet" href="assets/app.css">';
    echo '</head><body>';
}

function pnet_end(): void
{
    echo '</body></html>';
}
