use crate::error::ServiceError;
use crate::BoxFut;
use actix_service::Service;
use actix_service::Transform;
use actix_web::dev::Payload;
use actix_web::dev::ServiceRequest;
use actix_web::dev::ServiceResponse;
use actix_web::Error;
use actix_web::FromRequest;
use actix_web::HttpMessage;
use actix_web::HttpRequest;
use dino_park_oidc::provider::Provider;
use dino_park_trust::AALevel;
use futures::future;
use futures::future::ok;
use futures::future::Ready;
use futures::task::Context;
use futures::task::Poll;
use futures::TryFutureExt;
use std::cell::RefCell;
use std::sync::Arc;

#[derive(Clone)]
pub struct Groups {
    pub user_id: String,
    pub groups: Vec<String>,
    pub aa_level: AALevel,
}

impl Groups {
    pub fn public() -> Self {
        Groups {
            user_id: Default::default(),
            groups: Default::default(),
            aa_level: AALevel::Unknown,
        }
    }
}

#[derive(Clone)]
pub struct GroupsFromToken {
    pub checker: Provider,
}

impl GroupsFromToken {
    pub fn new(checker: Provider) -> Self {
        GroupsFromToken { checker }
    }
}

#[derive(Clone)]
pub struct GroupsFromTokenMiddleware<S> {
    pub service: Arc<RefCell<S>>,
    pub checker: Arc<Provider>,
}

impl<S, B: 'static> Transform<S> for GroupsFromToken
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type InitError = ();
    type Transform = GroupsFromTokenMiddleware<S>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        ok(GroupsFromTokenMiddleware {
            service: Arc::new(RefCell::new(service)),
            checker: Arc::new(self.checker.clone()),
        })
    }
}

impl<S, B> Service for GroupsFromTokenMiddleware<S>
where
    S: Service<Request = ServiceRequest, Response = ServiceResponse<B>, Error = Error> + 'static,
    S::Future: 'static,
    B: 'static,
{
    type Request = ServiceRequest;
    type Response = ServiceResponse<B>;
    type Error = Error;
    type Future = BoxFut<Self::Response, Self::Error>;

    fn poll_ready(&mut self, cx: &mut Context) -> Poll<Result<(), Self::Error>> {
        (*self.service).borrow_mut().poll_ready(cx)
    }

    fn call(&mut self, req: ServiceRequest) -> Self::Future {
        use crate::check::TokenChecker;
        use biscuit::StringOrUri;
        use biscuit::ValidationOptions;

        let svc = self.service.clone();
        let auth_token = match req
            .headers()
            .get("x-auth-token")
            .and_then(|value| value.to_str().ok())
        {
            Some(auth_token) => auth_token.to_owned(),
            None => return Box::pin(future::err(ServiceError::Unauthorized.into())),
        };
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
            let mut claims_set = fut
                .map_err(|_| Error::from(ServiceError::Unauthorized))
                .await?;

            if Provider::check(&claims_set, ValidationOptions::default()).is_err() {
                return Err(ServiceError::Unauthorized.into());
            }

            match claims_set.registered.subject {
                Some(StringOrUri::String(ref sub)) if sub != &user_id => {
                    return Err(ServiceError::Unauthorized.into())
                }
                _ => {}
            }

            let groups = serde_json::from_value::<Vec<String>>(
                claims_set.private["https://sso.mozilla.com/claim/groups"].take(),
            )
            .unwrap_or_default();
            let aa_level = serde_json::from_value::<AALevel>(
                claims_set.private["https://sso.mozilla.com/claim/AAL"].take(),
            )
            .unwrap_or(AALevel::Unknown);
            let groups = Groups {
                user_id,
                groups,
                aa_level,
            };
            req.extensions_mut().insert(groups);
            let fut = { svc.borrow_mut().call(req) };
            fut.await
        })
    }
}

impl FromRequest for Groups {
    type Config = ();
    type Error = Error;
    type Future = BoxFut<Self, Self::Error>;

    #[inline]
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {
        if let Some(groups) = req.extensions().get::<Groups>() {
            Box::pin(future::ok(groups.clone()))
        } else {
            Box::pin(future::err(ServiceError::Unauthorized.into()))
        }
    }
}
