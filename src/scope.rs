use crate::error::ServiceError;
use actix_service::Service;
use actix_service::Transform;
use actix_web::dev::Payload;
use actix_web::dev::*;
use actix_web::Error;
use actix_web::FromRequest;
use actix_web::HttpMessage;
use actix_web::HttpRequest;
use dino_park_oidc::provider::Provider;
use dino_park_trust::AALevel;
use dino_park_trust::GroupsTrust;
use dino_park_trust::Trust;
use futures::future;
use futures::future::ok;
use futures::future::LocalBoxFuture;
use futures::future::Ready;
use std::cell::RefCell;
use std::sync::Arc;

#[cfg(feature = "localuserscope")]
use futures::TryFutureExt;

#[derive(Clone)]
pub struct ScopeAndUser {
    pub user_id: String,
    pub scope: Trust,
    pub groups_scope: GroupsTrust,
    pub aa_level: AALevel,
}

impl ScopeAndUser {
    pub fn public() -> Self {
        ScopeAndUser {
            user_id: Default::default(),
            scope: Trust::Public,
            groups_scope: GroupsTrust::None,
            aa_level: AALevel::Unknown,
        }
    }
}

#[derive(Clone)]
pub struct ScopeAndUserAuth {
    pub checker: Provider,
    pub public: bool,
}

impl ScopeAndUserAuth {
    pub fn new(checker: Provider) -> Self {
        ScopeAndUserAuth {
            checker,
            public: false,
        }
    }

    pub fn public(mut self) -> Self {
        self.public = true;
        self
    }
}

#[derive(Clone)]
pub struct ScopeAndUserAuthMiddleware<S> {
    pub service: Arc<RefCell<S>>,
    pub checker: Arc<Provider>,
    pub public: bool,
}

impl<S> Transform<S, ServiceRequest> for ScopeAndUserAuth
where
    S: Service<ServiceRequest, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type InitError = ();
    type Transform = ScopeAndUserAuthMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(ScopeAndUserAuthMiddleware {
            service: Arc::new(RefCell::new(service)),
            checker: Arc::new(self.checker.clone()),
            public: self.public,
        })
    }
}

/// A M2M's subject is the client_id of the application, not whoever we gave the
/// token to. We pass along "ownership" as a custom claim during the credentials
/// exchange. The "assumed role" claim is a property of the M2M token, as a part
/// of its metadata in Auth0.
///
// Allow dead code because this isn't used when the test suite is ran.
#[allow(dead_code)]
fn known_subject_from_claim(
    subject_claimed: Option<String>,
    role: serde_json::Value,
    user_id: String,
) -> bool {
    let subject = serde_json::from_value::<String>(role)
        .ok()
        .or(subject_claimed);
    matches!(subject, Some(ref sub) if sub == &user_id)
}

impl<S> Service<ServiceRequest> for ScopeAndUserAuthMiddleware<S>
where
    S: Service<ServiceRequest, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_service::forward_ready!(service);

    #[cfg(feature = "localuserscope")]
    fn call(&self, req: ServiceRequest) -> Self::Future {
        let svc = self.service.clone();
        Box::pin(async { local_user_scope() }.and_then(move |scope| {
            req.extensions_mut().insert(scope);
            (*svc).borrow_mut().call(req)
        }))
    }

    #[cfg(not(feature = "localuserscope"))]
    fn call(&self, req: ServiceRequest) -> Self::Future {
        use crate::check::TokenChecker;
        use biscuit::ValidationOptions;

        let svc = self.service.clone();
        let auth_token = match (
            req.headers()
                .get("x-auth-token")
                .and_then(|value| value.to_str().ok()),
            self.public,
        ) {
            (Some(auth_token), _) => auth_token.to_owned(),
            (None, false) => return Box::pin(future::err(ServiceError::Unauthorized.into())),
            (None, true) => {
                return Box::pin(async move {
                    req.extensions_mut().insert(ScopeAndUser::public());
                    let fut = { svc.borrow_mut().call(req) };
                    fut.await
                })
            }
        };

        // DEBT?: Why do we need this if everything is in the claims? When would
        // gatekeeper forward us two unrelated items?
        let user_id = match req
            .headers()
            .get("x-forwarded-user-subject")
            .or_else(|| req.headers().get("x-auth-subject"))
            .and_then(|id| id.to_str().ok())
            .map(|id| id.to_owned())
        {
            Some(user_id) => user_id,
            None => return Box::pin(future::err(ServiceError::Unauthorized.into())),
        };

        let fut = <Provider as TokenChecker>::verify_and_decode(&self.checker, auth_token);
        Box::pin(async move {
            let mut claims_set = fut.await?;

            if Provider::check(&claims_set, ValidationOptions::default()).is_err() {
                return Err(ServiceError::Unauthorized.into());
            }

            if !known_subject_from_claim(
                claims_set.registered.subject,
                claims_set.private["https://sso.mozilla.com/claim/subject_assumed"].take(),
                user_id.clone(),
            ) {
                return Err(ServiceError::Unauthorized.into());
            }

            let groups = serde_json::from_value::<Vec<String>>(
                claims_set.private["https://sso.mozilla.com/claim/groups"].take(),
            )
            .ok();
            let scope = scope_from_claimset(&groups);
            let aa_level = serde_json::from_value::<AALevel>(
                claims_set.private["https://sso.mozilla.com/claim/AAL"].take(),
            )
            .unwrap_or(AALevel::Unknown);
            let scope_and_user = match scope {
                None => return Err(ServiceError::Unauthorized.into()),
                Some(scope) => ScopeAndUser {
                    user_id,
                    scope,
                    groups_scope: groups_scope_from_claimset(&groups),
                    aa_level,
                },
            };
            req.extensions_mut().insert(scope_and_user);
            let fut = { svc.borrow_mut().call(req) };
            fut.await
        })
    }
}

impl FromRequest for ScopeAndUser {
    type Error = Error;
    type Future = LocalBoxFuture<'static, Result<Self, Self::Error>>;

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(scope_and_user) = req.extensions().get::<ScopeAndUser>() {
            Box::pin(future::ok(scope_and_user.clone()))
        } else {
            Box::pin(future::err(ServiceError::Unauthorized.into()))
        }
    }
}

#[cfg(not(feature = "localuserscope"))]
fn scope_from_claimset(claims_set: &Option<Vec<String>>) -> Option<Trust> {
    if let Some(groups) = claims_set {
        let scope = if groups.contains(&String::from("team_moco"))
            || groups.contains(&String::from("team_mofo"))
            || groups.contains(&String::from("team_mozillaonline"))
            || groups.contains(&String::from("team_mozorg"))
            || groups.contains(&String::from("team_mzla"))
            || groups.contains(&String::from("team_mzai"))
            || groups.contains(&String::from("team_mzvc"))
            || groups.contains(&String::from("mozilliansorg_ghe_group_curators"))
            || groups.contains(&String::from("team_office_support"))
        {
            Trust::Staff
        } else if groups.contains(&String::from("mozilliansorg_nda"))
            || groups.contains(&String::from("mozilliansorg_contingentworkernda"))
        /*
            The NDA'd groups are defined in 3 places and have
            been referred to int he following pull requests to be
            used below as reference.
            https://github.com/mozilla-iam/dino-park-packs/pull/20
            https://github.com/mozilla-iam/dino-park-front-end/pull/662
        */
        {
            Trust::Ndaed
        } else {
            Trust::Authenticated
        };
        return Some(scope);
    }
    None
}

#[cfg(not(feature = "localuserscope"))]
fn groups_scope_from_claimset(claims_set: &Option<Vec<String>>) -> GroupsTrust {
    if let Some(groups) = claims_set {
        if groups.contains(&String::from("mozilliansorg_group_admins")) {
            return GroupsTrust::Admin;
        }
        if groups.contains(&String::from("mozilliansorg_group_creators")) {
            return GroupsTrust::Creator;
        }
    }
    GroupsTrust::None
}

#[cfg(feature = "localuserscope")]
fn local_user_scope() -> Result<ScopeAndUser, Error> {
    use log::info;
    use std::convert::TryFrom;
    use std::env::var;

    let dpg_userscope = "DPG_USERSCOPE";
    let user_scope = var(dpg_userscope).map_err(|_| ServiceError::Unauthorized)?;
    info!("using {}: {}", dpg_userscope, user_scope);
    let mut tuple = user_scope.split(',');
    let user_id = tuple.next().ok_or(ServiceError::Unauthorized)?.to_owned();
    let scope = tuple.next().ok_or(ServiceError::Unauthorized)?;
    let scope = Trust::try_from(scope).map_err(|_| ServiceError::Unauthorized)?;
    let groups_scope = tuple.next().unwrap_or_default();
    let groups_scope =
        GroupsTrust::try_from(groups_scope).map_err(|_| ServiceError::Unauthorized)?;
    let aa_level = match tuple.next() {
        Some(s) => AALevel::from(s),
        _ => AALevel::Unknown,
    };
    Ok(ScopeAndUser {
        user_id,
        scope,
        groups_scope,
        aa_level,
    })
}

#[cfg(test)]
mod test {
    use super::*;

    #[cfg(feature = "localuserscope")]
    use std::env::set_var;

    #[cfg(feature = "localuserscope")]
    #[test]
    fn test_local_user_scope() -> Result<(), Error> {
        set_var("DPG_USERSCOPE", "user_id,staff,admin,HIGH");
        let user_scope = local_user_scope()?;
        assert_eq!(user_scope.user_id, "user_id");
        assert_eq!(user_scope.scope, Trust::Staff);
        assert_eq!(user_scope.groups_scope, GroupsTrust::Admin);
        assert_eq!(user_scope.aa_level, AALevel::High);
        Ok(())
    }

    #[test]
    fn test_role_assume_no_role() {
        // The claim's subject and the HTTP header need to match. This test case
        // _should_ have been covered already, but just writing it out just in
        // case.
        let passed = known_subject_from_claim(
            Some("ad|Mozilla-LDAP|bpersaud".to_string()),
            serde_json::Value::Null,
            "ad|Mozilla-LDAP|bpersaud".to_string(),
        );
        assert_eq!(passed, true);
    }

    #[test]
    fn test_role_assume_m2m() {
        // The claim's subject and the HTTP header need to match. This test case
        // _should_ have been covered already, but just writing it out just in
        // case.
        let passed = known_subject_from_claim(
            Some("some-fake-client-id".to_string()),
            "ad|Mozilla-LDAP|bpersaud".into(),
            "ad|Mozilla-LDAP|bpersaud".to_string(),
        );
        assert_eq!(passed, true);
    }
}
