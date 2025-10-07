use chrono::{DateTime, Utc};
use color_eyre::eyre::{eyre, ContextCompat, OptionExt};
use reqwest::Url;
use base64::{engine::general_purpose, Engine};
use serde_json::Value;

pub fn get_jwt_exp(jwt: &str) -> color_eyre::Result<DateTime<Utc>> {
    let body = jwt.split('.').nth(1).ok_or_eyre("Invalid JWT")?;
    let decoded = general_purpose::URL_SAFE_NO_PAD.decode(body)?;
    let parsed: Value = serde_json::from_slice(&decoded)?;

    let exp = match parsed.get("exp") {
        Some(Value::Number(n)) => match n.as_i64() {
            Some(v) => Ok(v),
            None => Err(eyre!("Unable to represent exp as i64")),
        }
        _ => Err(eyre!("Unable to parse exp field in JWT")),
    }?;

    DateTime::from_timestamp(exp, 0)
        .wrap_err("Invalid exp timestamp")
}

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

    #[test]
    fn test_get_jwt_exp() {
        let jwt = "abc.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZXhwIjoxNzU5ODUwNzc2fQ.xyz";
        let exp = get_jwt_exp(jwt).unwrap();
        let expected = DateTime::from_timestamp(1759850776, 0).unwrap();

        assert_eq!(exp, expected)
    }
}
