//! Indicators of compromise for the NIKKE PC launcher compromise (2026-09-27 ~ 2026-11-04).
//!
//! Source: MotherSphere/NIKKE-Launcher-Check (GPL-3.0) docs/incident.md and docs/checks.md,
//! and the public write-up linked there.

/// Domains used by the loader and the agent.
pub const DOMAINS: [&str; 3] = ["insightjs.com", "analytics.insightjs.com", "insightjs.org"];

/// Attacker and still-modified CDN addresses.
pub const IPS: [(&str, &str); 4] = [
    ("89.127.233.127", "insight.bundle 배포 서버"),
    ("89.126.250.172", "insightjs.com 이전 주소"),
    ("43.175.144.148", "변조 파일 배포 CDN"),
    ("43.175.145.181", "변조 파일 배포 CDN"),
];

/// Only these two are the attacker's own servers; the CDN addresses also serve normal files.
pub const BLOCK_IPS: [&str; 2] = ["89.127.233.127", "89.126.250.172"];

/// Text that marks the agent server (critical when found).
pub const AGENT_SERVER: [&str; 2] = ["analytics.insightjs.com", "insight.bundle"];

/// Text that marks the loader (warning when found alone).
pub const LOADER: &str = "insightjs";

/// The agent's bridge channel and Local Storage key.
pub const AGENT_MARKS: [&str; 2] = ["k2f_chan", "k2f.agent"];

/// debug.log lines that make up the agent's runs.
pub const RUN_LINES: [&str; 6] = [
    "k2f_chan registered",
    "adopted ",
    "resuming ",
    "agent started as",
    "lua downloaded to",
    "startup already in progress",
];

/// LuaJIT bytecode header: the saved agent itself.
pub const LUAJIT_MAGIC: [u8; 3] = [0x1B, 0x4C, 0x4A];

/// Size of the known agent builds.
pub const AGENT_SIZE: u64 = 205_135;

/// Chrome persistence COM class.
pub const CLSID: &str = "{E77CC89B-7401-4C04-8CED-149DB35ADD04}";
pub const CLSID_KEY: &str = r"Software\Classes\CLSID\{E77CC89B-7401-4C04-8CED-149DB35ADD04}";
pub const PEH_DIR: &str = "PlatformExperienceHelper";
pub const PEH_DLL: &str = "platform_experience_helper.dll";
/// Files of an older persistence version in Chrome's own Application folder.
pub const OLD_PEH_FILES: [&str; 3] = [
    "platform_experience_helper.dll",
    "platform_experience_helper.dll.old",
    "old-clsid.txt",
];

/// Agent temp file prefix (k2f-bcreds-*, k2f_screen_*.jpg).
pub const TEMP_PREFIX: &str = "k2f";

pub const LAUNCHER_EXE: &str = "nikke_launcher.exe";
pub const LAUNCHER_DATA_DIRS: [&str; 2] = ["nikke_launcher", "nikke_launcher_hmt"];

/// The agent was served from this day at the latest (local date).
pub const AGENT_FROM: &str = "2026-10-23";
/// 2026-10-23 00:00:00 UTC, as Unix seconds.
pub const AGENT_FROM_UNIX: u64 = 1_792_713_600;

/// Chromium browsers whose user data the agent can target with the DLL, and whose
/// logins and extensions it can read. (name, path under the Windows profile)
pub const CHROMIUM: [(&str, &str); 7] = [
    ("Chrome", "AppData/Local/Google/Chrome/User Data"),
    ("Edge", "AppData/Local/Microsoft/Edge/User Data"),
    ("Brave", "AppData/Local/BraveSoftware/Brave-Browser/User Data"),
    ("Vivaldi", "AppData/Local/Vivaldi/User Data"),
    ("Opera", "AppData/Roaming/Opera Software/Opera Stable"),
    ("Opera GX", "AppData/Roaming/Opera Software/Opera GX Stable"),
    ("Chromium", "AppData/Local/Chromium/User Data"),
];

pub const FIREFOX: &str = "AppData/Roaming/Mozilla/Firefox/Profiles";

/// The 28 extension IDs of the agent's wallet_files command.
pub const WALLETS: [(&str, &str); 28] = [
    ("acmacodkjbdgmoleebolmdjonilkdbch", "Rabby"),
    ("aflkmfhebedbjioipglgcbcmnbpgliof", "Backpack"),
    ("bfnaelmomeimhlpmgjnjophhpkkoljpa", "Phantom"),
    ("bhhhlbepdkbapadjdnnojkbgioiodbic", "Solflare"),
    ("cadiboklkpojfamcoggejbbdjcoiljjk", "Binance Wallet"),
    ("dmkamcknogkgcdfhhbddcghachkejeap", "Keplr"),
    ("egjidjbpglichdcondbcbdnbeeppgdph", "Trust Wallet"),
    ("fnjhmkhhmkbjkkabndcnnogagogbneec", "Ronin Wallet"),
    ("ibnejdfjmmkpcnlpebklmnkoeoihofec", "TronLink"),
    ("jiidiaalihmmhddjgbnbgdfflelocpak", "Bitget Wallet"),
    ("mcohilncbfahbmgdjkbpemcciiolgcge", "OKX Wallet"),
    ("nkbihfbeogaeaoehlefnkodbefgpgknn", "MetaMask"),
    ("omaabbefbmiijedngplfjmnooppbclkk", "Tonkeeper"),
    ("opcgpfmipidbgpenhmajoajpbobppdil", "Slush"),
    ("pdliaogehgdbhbnmkklieghmmjkpigpa", "Bybit Wallet"),
    ("jblndlipeogpafnldhgmapagcccfchpi", "Kaia Wallet"),
    ("aiifbnbfobpmeekipheeijimdpnlpgpp", "Station"),
    ("ppbibelpcjmhbdihakflkdcoccbgbkpo", "UniSat"),
    ("idnnbdplmphpflfnlkomgpfbpcgelopg", "Xverse"),
    ("mkpegjkblkkefacfnmkajcjmabijhclg", "Magic Eden"),
    ("ejjladinnckdgjemekebdpeokbikhfci", "Petra"),
    ("dlcobpjiigpikoobohmabehhmhfoodbb", "Ready"),
    ("gjagmgiddbbciopjhllkdnddhcglnemk", "HashPack"),
    ("onhogfjeacnfoofkfgppdlbmlmnplgbn", "SubWallet"),
    ("opfgelmcmbiajamepnmloijbpoleiama", "Rainbow"),
    ("jnlgamecbpmbajjfhmmmlhejkemejdma", "Braavos"),
    ("phkbamefinggmakgklpkljjmgibohnba", "Pontem"),
    ("hnfanknocfeofbddgcijnmhnfnkdnaad", "Coinbase Wallet"),
];

/// Secret files from the agent's keyscan list, relative to the Windows profile.
/// SSH private keys (.ssh/id_*) are found separately.
pub const SECRETS: [(&str, &str); 22] = [
    ("AWS 자격 증명", ".aws/credentials"),
    ("GitHub CLI 토큰", ".config/gh/hosts.yml"),
    ("GitHub CLI 토큰", "AppData/Roaming/GitHub CLI/hosts.yml"),
    ("Git 자격 증명", ".git-credentials"),
    ("npm 토큰", ".npmrc"),
    ("Docker 로그인", ".docker/config.json"),
    ("Kubernetes 설정", ".kube/config"),
    ("Google Cloud 자격 증명", "AppData/Roaming/gcloud/credentials.db"),
    (
        "Google Cloud 자격 증명",
        "AppData/Roaming/gcloud/application_default_credentials.json",
    ),
    ("Azure CLI 토큰", ".azure/msal_token_cache.bin"),
    ("Azure CLI 토큰", ".azure/msal_token_cache.json"),
    ("Claude Code 자격 증명", ".claude/.credentials.json"),
    ("Codex CLI 자격 증명", ".codex/auth.json"),
    ("Gemini CLI 자격 증명", ".gemini/oauth_creds.json"),
    ("FileZilla 저장 서버", "AppData/Roaming/FileZilla/sitemanager.xml"),
    ("FileZilla 저장 서버", "AppData/Roaming/FileZilla/recentservers.xml"),
    ("netrc 로그인", "_netrc"),
    ("PyPI 토큰", ".pypirc"),
    ("crates.io 토큰", ".cargo/credentials.toml"),
    ("Hugging Face 토큰", ".cache/huggingface/token"),
    ("GnuPG 개인 키", "AppData/Roaming/gnupg/private-keys-v1.d"),
    (".env 파일", ".env"),
];

/// Folders a walk never enters.
pub const SKIP_DIRS: [&str; 9] = [
    "$recycle.bin",
    "system volume information",
    "node_modules",
    ".git",
    ".cache",
    "dosdevices",
    "windowsapps",
    "winsxs",
    "$windows.~ws",
];
