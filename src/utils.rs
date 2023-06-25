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

#[cfg(test)]
mod tests {
    use reqwest::Url;

    use crate::utils::create_inspector_url;

    #[test]
    fn test_create_inspector_url() {
        let download_url: Url = "https://files.pythonhosted.org/packages/cb/63/f897bdaa98710f9cb96ca1391742192975a776dc70a5a7b0acfbab50b20b/letsbuilda_pypi-4.0.0-py3-none-any.whl".parse().unwrap();
        let inspector_url: Url = "https://inspector.pypi.io/project/letsbuilda-pypi/4.0.0/packages/cb/63/f897bdaa98710f9cb96ca1391742192975a776dc70a5a7b0acfbab50b20b/letsbuilda_pypi-4.0.0-py3-none-any.whl/".parse().unwrap();

        assert_eq!(create_inspector_url("letsbuilda_pypi", "4.0.0", &download_url), inspector_url)
    }
}
