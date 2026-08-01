use reqwest::Url;

#[allow(clippy::doc_markdown)] // Clippy thinks PyPI is a documentation item
/// Turn a package `name`, `version`, and `download_url` into a PyPI Inspector URL
pub fn create_inspector_url(name: &str, version: &str, download_url: &Url) -> Url {
    let mut download_url = download_url.clone();
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
    use super::*;

    macro_rules! create_inspector_url_tests {
        ($($name:ident: $value:expr,)*) => {
            $(
                #[test]
                fn $name() {
                    let ((n, version, download_url), exp) = $value;
                    assert_eq!(exp, create_inspector_url(n, version, &download_url));
                }
            )*
        }
    }

    create_inspector_url_tests! {
        create_inspector_url_0: (
            ("numpy", "1.24.3", Url::parse("https://files.pythonhosted.org/packages/f3/23/7cc851bae09cf4db90d42a701dfe525780883ada86bece45e3da7a07e76b/numpy-1.24.3-cp310-cp310-macosx_10_9_x86_64.whl/numpy/__init__.pyi").unwrap()),
            Url::parse("https://inspector.pypi.io/project/numpy/1.24.3/packages/f3/23/7cc851bae09cf4db90d42a701dfe525780883ada86bece45e3da7a07e76b/numpy-1.24.3-cp310-cp310-macosx_10_9_x86_64.whl/numpy/__init__.pyi/").unwrap(),
        ),
        create_inspector_url_1: (
            ("numpy", "1.24.3", Url::parse("https://files.pythonhosted.org/packages/f3/23/7cc851bae09cf4db90d42a701dfe525780883ada86bece45e3da7a07e76b/numpy-1.24.3-cp310-cp310-macosx_10_9_x86_64.whl/numpy/typing/tests/data/fail/twodim_base.pyi").unwrap()),
            Url::parse("https://inspector.pypi.io/project/numpy/1.24.3/packages/f3/23/7cc851bae09cf4db90d42a701dfe525780883ada86bece45e3da7a07e76b/numpy-1.24.3-cp310-cp310-macosx_10_9_x86_64.whl/numpy/typing/tests/data/fail/twodim_base.pyi/").unwrap()
        ),
        create_inspector_url_2: (
            ("discord-py","2.2.3", Url::parse("https://files.pythonhosted.org/packages/36/ce/3ad5a63240b504722dada49d880f9f6250ab861baaba5d27df4f4cb3e34a/discord.py-2.2.3.tar.gz/discord.py-2.2.3/discord/app_commands/checks.py").unwrap()),
            Url::parse("https://inspector.pypi.io/project/discord-py/2.2.3/packages/36/ce/3ad5a63240b504722dada49d880f9f6250ab861baaba5d27df4f4cb3e34a/discord.py-2.2.3.tar.gz/discord.py-2.2.3/discord/app_commands/checks.py/").unwrap()
        ),
        create_inspector_url_3: (
            ("requests", "2.19.1", Url::parse("https://files.pythonhosted.org/packages/54/1f/782a5734931ddf2e1494e4cd615a51ff98e1879cbe9eecbdfeaf09aa75e9/requests-2.19.1.tar.gz/requests-2.19.1/LICENSE").unwrap()),
            Url::parse("https://inspector.pypi.io/project/requests/2.19.1/packages/54/1f/782a5734931ddf2e1494e4cd615a51ff98e1879cbe9eecbdfeaf09aa75e9/requests-2.19.1.tar.gz/requests-2.19.1/LICENSE/").unwrap()
        ),
    }
}
