use super::{available_bytes, database::Database, model::*, Cancel, GeoIpManager};
use anyhow::{bail, Context, Result};
use serde::Deserialize;
use sha2::{Digest, Sha256};
use std::{
    fs,
    os::unix::fs::{OpenOptionsExt, PermissionsExt},
    path::Path,
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

const RELEASE_API: &str = "https://api.github.com/repos/P3TERX/GeoLite.mmdb/releases/latest";
const SOURCE: &str = "GeoLite2 / P3TERX";
const SPACE_RESERVE: u64 = 1024 * 1024;
pub(super) struct Prepared {
    pub directory: tempfile::TempDir,
    pub profile: Profile,
    pub version: String,
    pub source: String,
}
#[derive(Deserialize)]
pub(super) struct Release {
    pub tag_name: String,
    pub assets: Vec<Asset>,
}
#[derive(Clone, Deserialize)]
pub(super) struct Asset {
    pub name: String,
    pub size: u64,
    pub digest: Option<String>,
    pub browser_download_url: String,
}
impl Release {
    pub(super) fn selected(&self, profile: Profile) -> Result<Vec<(Kind, Asset)>> {
        if self.tag_name.is_empty()
            || self.tag_name.len() > 64
            || !self.tag_name.bytes().all(|c| c.is_ascii_alphanumeric() || b"._-".contains(&c))
        {
            bail!("Invalid database release version");
        }
        profile
            .files()
            .iter()
            .map(|kind| {
                let asset = self
                    .assets
                    .iter()
                    .find(|a| a.name == kind.filename())
                    .context("The selected database is missing from the release")?;
                let expected_url = format!(
                    "https://github.com/P3TERX/GeoLite.mmdb/releases/download/{}/{}",
                    self.tag_name,
                    kind.filename()
                );
                if asset.browser_download_url != expected_url || asset.size == 0 || asset.size > MAX_FILE_BYTES {
                    bail!("Invalid database download metadata");
                }
                let digest = asset
                    .digest
                    .as_deref()
                    .and_then(|s| s.strip_prefix("sha256:"))
                    .context("The download source did not provide a SHA-256 checksum")?;
                if digest.len() != 64 || !digest.bytes().all(|c| c.is_ascii_hexdigit()) {
                    bail!("Invalid database checksum");
                }
                Ok((*kind, asset.clone()))
            })
            .collect()
    }
}
impl GeoIpManager {
    pub(super) async fn download(&self, profile: Profile, cancel: &Cancel) -> Result<Option<Prepared>> {
        let client = reqwest::Client::builder()
            .https_only(true)
            .connect_timeout(Duration::from_secs(10))
            .read_timeout(Duration::from_secs(30))
            .timeout(Duration::from_secs(20 * 60))
            .redirect(reqwest::redirect::Policy::limited(5))
            .user_agent(concat!("Bandix/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let mut response = client
            .get(RELEASE_API)
            .timeout(Duration::from_secs(25))
            .header("Accept", "application/vnd.github+json")
            .send()
            .await
            .context("Cannot reach the database release source")?
            .error_for_status()
            .context("Cannot read the database release; the source may be rate limited")?;
        let mut metadata = Vec::new();
        while let Some(chunk) = response.chunk().await? {
            if metadata.len() + chunk.len() > 1024 * 1024 {
                bail!("Database release metadata is too large");
            }
            metadata.extend_from_slice(&chunk);
        }
        let release: Release = serde_json::from_slice(&metadata).context("Invalid database release response")?;
        let selected = release.selected(profile)?;
        {
            let state = self.state.lock().unwrap();
            if state.settings.version == release.tag_name
                && state.settings.profile == profile
                && state.settings.source == SOURCE
                && state.databases.len() == selected.len()
                && state.databases.iter().all(|db| {
                    selected
                        .iter()
                        .any(|(kind, asset)| *kind == db.info.kind && asset.size == db.info.bytes)
                })
            {
                return Ok(None);
            }
        }
        let total = selected.iter().map(|(_, a)| a.size).sum();
        self.phase("checking_space");
        {
            let mut state = self.state.lock().unwrap();
            state.job.total_bytes = Some(total);
            state.job.required_bytes = Some(total.saturating_add(SPACE_RESERVE));
        }
        ensure_space(&self.directory, total)?;
        let directory = tempfile::Builder::new().prefix(".download-").tempdir_in(&self.directory)?;
        for (kind, asset) in selected {
            cancel.check()?;
            {
                let mut state = self.state.lock().unwrap();
                state.job.phase = "downloading".into();
                state.job.current_file = Some(asset.name.clone());
            }
            let path = directory.path().join(kind.filename());
            let mut response = client
                .get(&asset.browser_download_url)
                .send()
                .await
                .context("Cannot connect to the database download server")?
                .error_for_status()
                .context("Database download failed")?;
            let mut file = tokio::fs::File::create(&path)
                .await
                .context("Cannot create database download file")?;
            let mut hasher = Sha256::new();
            let mut received = 0u64;
            while let Some(chunk) = response.chunk().await.context("Database download interrupted")? {
                cancel.check()?;
                received += chunk.len() as u64;
                if received > asset.size {
                    bail!("Database download exceeds the advertised size");
                }
                file.write_all(&chunk)
                    .await
                    .context("Cannot write database; check available storage")?;
                hasher.update(&chunk);
                self.progress(chunk.len() as u64);
            }
            file.sync_all().await?;
            drop(file);
            self.phase("verifying");
            let digest = format!("{:x}", hasher.finalize());
            verify_digest(&asset, received, &digest)?;
            verify_file(path, Some(kind)).await?;
        }
        Ok(Some(Prepared {
            directory,
            profile,
            version: release.tag_name,
            source: SOURCE.into(),
        }))
    }
    pub(super) async fn import(&self, cancel: &Cancel) -> Result<Prepared> {
        self.import_path(Path::new(UPLOAD_PATH), cancel).await
    }

    pub(super) async fn import_path(&self, upload: &Path, cancel: &Cancel) -> Result<Prepared> {
        // The upload RPC exposes exactly one staging path. Never follow symlinks
        // or accept an arbitrary filesystem path supplied through an API request.
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(upload)
            .context("Upload a database file first")?;
        let metadata = file.metadata()?;
        if !metadata.is_file() || metadata.len() == 0 || metadata.len() > MAX_FILE_BYTES {
            bail!("Upload must be a regular MMDB file smaller than 128 MiB");
        }
        let old = self.state.lock().unwrap().settings.clone();
        let existing_bytes = self.status().installed_bytes;
        self.phase("checking_space");
        self.state.lock().unwrap().job.required_bytes = Some(metadata.len().saturating_add(existing_bytes).saturating_add(SPACE_RESERVE));
        ensure_space(&self.directory, metadata.len() + existing_bytes)?;
        let directory = tempfile::Builder::new().prefix(".download-").tempdir_in(&self.directory)?;
        let staged = directory.path().join("upload.mmdb");
        let mut input = tokio::fs::File::from_std(file);
        let mut output = tokio::fs::File::create(&staged).await?;
        self.state.lock().unwrap().job.total_bytes = Some(metadata.len());
        self.phase("importing");
        let mut buffer = [0u8; 65536];
        let mut received = 0;
        loop {
            cancel.check()?;
            let n = input.read(&mut buffer).await?;
            if n == 0 {
                break;
            }
            received += n as u64;
            if received > metadata.len() {
                bail!("The uploaded file changed while it was being imported");
            }
            output.write_all(&buffer[..n]).await?;
            self.progress(n as u64);
        }
        output.sync_all().await?;
        drop(output);
        if received != metadata.len() {
            bail!("The uploaded file is incomplete");
        }
        self.phase("verifying");
        let kind = verify_file(staged.clone(), None).await?;
        fs::rename(&staged, directory.path().join(kind.filename()))?;
        let old_dir = old.active.as_ref().map(|name| self.directory.join(name));
        for previous in old.profile.files() {
            // A City upload replaces Country and vice versa. Keep an installed
            // ASN when uploading location data, or keep location data for ASN.
            let keep = *previous != kind && (*previous == Kind::Asn || kind == Kind::Asn);
            if keep {
                if let Some(old_dir) = &old_dir {
                    tokio::fs::copy(old_dir.join(previous.filename()), directory.path().join(previous.filename())).await?;
                }
            }
        }
        let city = directory.path().join(Kind::City.filename()).exists();
        let country = directory.path().join(Kind::Country.filename()).exists();
        let asn = directory.path().join(Kind::Asn.filename()).exists();
        if !country && !city {
            bail!("Upload a Country or City database before uploading ASN");
        }
        let profile = if city && asn {
            Profile::CityAsn
        } else if city {
            Profile::City
        } else if asn {
            Profile::CountryAsn
        } else {
            Profile::Country
        };
        Ok(Prepared {
            directory,
            profile,
            version: "local".into(),
            source: "Local upload".into(),
        })
    }
}
async fn verify_file(path: std::path::PathBuf, expected: Option<Kind>) -> Result<Kind> {
    tokio::task::spawn_blocking(move || {
        let database = Database::open(&path, expected, true)?;
        let kind = database.info.kind;
        drop(database);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o444))?;
        fs::File::open(path)?.sync_all()?;
        Ok(kind)
    })
    .await?
}
pub(super) fn ensure_space(path: &Path, needed: u64) -> Result<()> {
    let free = available_bytes(path)?;
    if free < needed.saturating_add(SPACE_RESERVE) {
        bail!(
            "Not enough free space: need {} bytes including temporary files, {} bytes available",
            needed.saturating_add(SPACE_RESERVE),
            free
        );
    }
    Ok(())
}
pub(super) fn verify_digest(asset: &Asset, bytes: u64, digest: &str) -> Result<()> {
    if bytes != asset.size {
        bail!("Database download is incomplete");
    }
    let expected = asset
        .digest
        .as_deref()
        .and_then(|s| s.strip_prefix("sha256:"))
        .context("Missing database checksum")?;
    if !expected.eq_ignore_ascii_case(digest) {
        bail!("Database SHA-256 checksum mismatch");
    }
    Ok(())
}
