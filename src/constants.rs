#[allow(dead_code)]
#[derive(Copy, Clone)]
pub enum Urls {
    Login,
    AuthCallback,
    AuthLogout,
    AdminLinks,
    AdminCreate,
    AdminEdit,
    AdminDelete,
}
impl Urls {
    pub fn as_str(&self) -> &str {
        match self {
            Urls::Login => "/auth/login",
            Urls::AuthCallback => "/oauth2/callback",
            Urls::AuthLogout => "/auth/logout",
            Urls::AdminLinks => "/admin/links",
            Urls::AdminCreate => "/admin/links/create",
            Urls::AdminEdit => "/admin/links/edit",
            Urls::AdminDelete => "/admin/links/delete",
        }
    }
}

impl AsRef<str> for Urls {
    fn as_ref(&self) -> &str {
        self.as_str()
    }
}

/// Things that are banned because they'll break routes
pub const BANNED_TAGS: &[&str] = &[
    "link",
    "admin",
    "preview",
    "login",
    "logout",
    "auth",
    "static",
    "healthcheck",
];
