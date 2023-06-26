use reqwest::Url;

/// Turn a package name, version, and download_url into a PyPI Inspector URL
pub fn create_inspector_url(name: &str, version: &str, download_url: &Url) -> Url {
    let mut download_url = download_url.to_owned();
    let new_path = format!(
        "project/{}/{}/{}/",
        name,
        version,
        download_url.path().strip_prefix('/').unwrap(),
    );

    download_url.set_host(Some("inspector.pypi.io")).unwrap();
    download_url.set_path(&new_path);
    
    download_url
}
