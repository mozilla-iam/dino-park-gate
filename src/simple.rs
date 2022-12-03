use crate::check::TokenChecker;
use crate::error::ServiceError;
use actix_service::Service;
use actix_service::Transform;
use actix_web::dev::*;
use actix_web::Error;
use biscuit::ValidationOptions;
use futures::future;
use futures::future::LocalBoxFuture;
use futures::future::Ready;
use std::cell::RefCell;
use std::sync::Arc;

#[derive(Clone)]
pub struct SimpleAuth<T: TokenChecker + 'static> {
    pub checker: T,
    pub validation_options: ValidationOptions,
}
#[derive(Clone)]
pub struct SimpleAuthMiddleware<S, T: TokenChecker + 'static> {
    pub service: Arc<RefCell<S>>,
    pub checker: Arc<T>,
    pub validation_options: ValidationOptions,
}

impl<S, T: TokenChecker + Clone + 'static> Transform<S, ServiceRequest> for SimpleAuth<T>
where
    S: Service<ServiceRequest, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type InitError = ();
    type Transform = SimpleAuthMiddleware<S, T>;
    type Future = Ready<Result<Self::Transform, Self::InitError>>;

    fn new_transform(&self, service: S) -> Self::Future {
        future::ok(SimpleAuthMiddleware {
            service: Arc::new(RefCell::new(service)),
            checker: Arc::new(self.checker.clone()),
            validation_options: self.validation_options.clone(),
        })
    }
}

impl<S, T: TokenChecker + 'static> Service<ServiceRequest> for SimpleAuthMiddleware<S, T>
where
    S: Service<ServiceRequest, Error = Error> + 'static,
    S::Future: 'static,
{
    type Response = S::Response;
    type Error = S::Error;
    type Future = LocalBoxFuture<'static, Result<Self::Response, Self::Error>>;

    actix_service::forward_ready!(service);

    fn call(&self, req: ServiceRequest) -> Self::Future {
        if req.method() == "OPTIONS" {
            let fut = { self.service.borrow_mut().call(req) };
            return Box::pin(fut);
        }

        let auth_header = match req.headers().get("AUTHORIZATION") {
            Some(value) => value.to_str().ok(),
            None => return Box::pin(async move { Err(ServiceError::Unauthorized.into()) }),
        };

        if let Some(auth_header) = auth_header {
            if let Some(token) = get_token(auth_header) {
                let svc = self.service.clone();
                let validation_options = self.validation_options.clone();
                let fut = self.checker.verify_and_decode(token.to_owned());
                return Box::pin(async move {
                    let claim_set = fut.await.map_err(|_| ServiceError::Forbidden)?;
                    match T::check(&claim_set, validation_options) {
                        Ok(_) => {
                            let fut = { svc.borrow_mut().call(req) };
                            fut.await
                        }
                        Err(_) => Err(ServiceError::Unauthorized.into()),
                    }
                });
            }
        }
        Box::pin(async move { Err(ServiceError::Unauthorized.into()) })
    }
}

fn get_token(auth_header: &str) -> Option<&str> {
    match auth_header.get(0..7) {
        Some("Bearer ") => auth_header.get(7..),
        _ => None,
    }
}
#[cfg(test)]
mod test {
    use super::*;
    use crate::error::ServiceError;
    use actix_service::IntoService;
    use actix_web::test::TestRequest;
    use actix_web::HttpResponse;
    use biscuit::ClaimsSet;
    use futures::future::ok;
    use futures::future::BoxFuture;
    use serde_json::Value;

    #[derive(Default, Clone)]
    struct FakeChecker {
        pub claim_set: Option<ClaimsSet<Value>>,
        pub token: Option<String>,
    }

    impl TokenChecker for FakeChecker {
        type Item = biscuit::ClaimsSet<Value>;
        type Future = BoxFuture<'static, Result<Self::Item, ServiceError>>;
        fn verify_and_decode(&self, token: String) -> Self::Future {
            if let Some(cs) = &self.claim_set {
                if self
                    .token
                    .as_ref()
                    .map(|t| t == &token)
                    .unwrap_or_else(|| true)
                {
                    return Box::pin(future::ok(cs.clone()));
                }
            };
            // TODO: review this clippy-disable with a rust expert [IAM-1024]
            #[allow(clippy::useless_conversion)]
            Box::pin(future::err(ServiceError::Unauthorized.into()))
        }
        fn check(
            item: &Self::Item,
            validation_options: ValidationOptions,
        ) -> Result<(), ServiceError> {
            item.registered
                .validate(validation_options)
                .map_err(Into::into)
        }
    }

    #[test]
    fn test_get_token() {
        let token = "Bearer FOOBAR…";
        assert_eq!(get_token(token), Some("FOOBAR…"));
    }

    #[actix_rt::test]
    async fn test_middleware_no_token() {
        let srv = |req: ServiceRequest| ok(req.into_response(HttpResponse::Ok()));
        let auth_middleware = SimpleAuth {
            checker: FakeChecker::default(),
            validation_options: ValidationOptions::default(),
        };
        let srv = auth_middleware
            .new_transform(srv.into_service())
            .await
            .unwrap();
        let req = TestRequest::default()
            .insert_header(("SOMETHING", "ELSE"))
            .to_srv_request();
        let res = srv.call(req).await;
        assert!(res.is_err());
    }

    #[actix_rt::test]
    async fn test_middleware_bearer_missing() {
        let srv = |req: ServiceRequest| ok(req.into_response(HttpResponse::Ok()));
        let auth_middleware = SimpleAuth {
            checker: FakeChecker {
                claim_set: Some(ClaimsSet {
                    registered: Default::default(),
                    private: Value::default(),
                }),
                token: None,
            },
            validation_options: ValidationOptions::default(),
        };
        let srv = auth_middleware
            .new_transform(srv.into_service())
            .await
            .unwrap();
        let req = TestRequest::default()
            .insert_header(("AUTHORIZATION", "not bearer"))
            .to_srv_request();
        let res = srv.call(req).await;
        assert!(res.is_err());
    }

    #[actix_rt::test]
    async fn test_middleware_authorized() {
        let srv = |req: ServiceRequest| ok(req.into_response(HttpResponse::Ok()));
        let auth_middleware = SimpleAuth {
            checker: FakeChecker {
                claim_set: Some(ClaimsSet {
                    registered: Default::default(),
                    private: Value::default(),
                }),
                token: None,
            },
            validation_options: ValidationOptions::default(),
        };
        let srv = auth_middleware
            .new_transform(srv.into_service())
            .await
            .unwrap();
        let req = TestRequest::default()
            .insert_header(("AUTHORIZATION", "Bearer somethingfun"))
            .to_srv_request();
        let res = srv.call(req).await;
        assert!(res.is_ok());
    }
}
