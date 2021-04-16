use actix_web::{http, test, App};
use async_trait::async_trait;
use std::fs;
use zian::{
    github_pull_request_webhook, AppConfig, DispatcherErr, DispatcherService,
    GitHubPullRequestWebhook,
};

use hmac::{Hmac, Mac, NewMac};
use sha2::Sha256;

type HmacSha256 = Hmac<Sha256>;

struct TestDispatcher {}

#[async_trait]
impl DispatcherService for TestDispatcher {
    async fn dispatch_pull_request(
        &self,
        _webhook: &GitHubPullRequestWebhook,
        _raw_webhook: &str,
        _headers: &actix_web::http::header::HeaderMap,
    ) -> Result<(), DispatcherErr> {
        Ok(())
    }
}

fn load_example_data() -> String {
    let file_name = "tests/resources/github-webhook.json";
    return fs::read_to_string(file_name).unwrap();
}

fn create_base_req() -> test::TestRequest {
    let data = load_example_data();
    let mut mac = HmacSha256::new_varkey(b"test-secret").expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let mac_bytes = mac.finalize().into_bytes();

    test::TestRequest::post()
        .header("content-type", "application/json")
        .header(
            "X-HUB-SIGNATURE-256",
            format!("sha256={}", hex::encode(mac_bytes)),
        )
        .uri("/github/pull_request")
        .set_payload(data)
}

#[actix_rt::test]
async fn test_ok() {
    let mut app = test::init_service(
        App::new()
            .data(AppConfig {
                insecure: false,
                github_secret: Some("test-secret".to_string()),
                dispatcher: Box::new(TestDispatcher {}),
            })
            .service(github_pull_request_webhook),
    )
    .await;

    let req = create_base_req().to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), http::StatusCode::OK);
}

#[actix_rt::test]
async fn test_no_secret() {
    let mut app = test::init_service(
        App::new()
            .data(AppConfig {
                insecure: false,
                github_secret: Some("test-secret".to_string()),
                dispatcher: Box::new(TestDispatcher {}),
            })
            .data(Box::new(TestDispatcher {}))
            .service(github_pull_request_webhook),
    )
    .await;
    let data = load_example_data();

    let req = test::TestRequest::post()
        .header("content-type", "application/json")
        .uri("/github/pull_request")
        .set_payload(data)
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_incorrect_secret() {
    let mut app = test::init_service(
        App::new()
            .data(AppConfig {
                insecure: false,
                github_secret: Some("test-secret".to_string()),
                dispatcher: Box::new(TestDispatcher {}),
            })
            .service(github_pull_request_webhook),
    )
    .await;
    let data = load_example_data();

    let mut mac =
        HmacSha256::new_varkey(b"incorrect-secret").expect("HMAC can take key of any size");
    mac.update(data.as_bytes());
    let mac_bytes = mac.finalize().into_bytes();

    let req = create_base_req()
        .header(
            "X-HUB-SIGNATURE-256",
            format!("sha256={}", hex::encode(mac_bytes)),
        )
        .to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
}

#[actix_rt::test]
async fn test_no_payload() {
    let mut app = test::init_service(
        App::new()
            .data(AppConfig {
                insecure: false,
                github_secret: Some("test-secret".to_string()),
                dispatcher: Box::new(TestDispatcher {}),
            })
            .service(github_pull_request_webhook),
    )
    .await;

    let req = create_base_req().set_payload("").to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), http::StatusCode::BAD_REQUEST);
}

#[actix_rt::test]
async fn test_bad_file() {
    struct TestDispatcherBadFile {}

    #[async_trait]
    impl DispatcherService for TestDispatcherBadFile {
        async fn dispatch_pull_request(
            &self,
            _webhook: &GitHubPullRequestWebhook,
            _raw_webhook: &str,
            _headers: &actix_web::http::header::HeaderMap,
        ) -> Result<(), DispatcherErr> {
            Err(DispatcherErr::NotSafe)
        }
    }

    let mut app = test::init_service(
        App::new()
            .data(AppConfig {
                insecure: false,
                github_secret: Some("test-secret".to_string()),
                dispatcher: Box::new(TestDispatcherBadFile {}),
            })
            .service(github_pull_request_webhook),
    )
    .await;

    let req = create_base_req().to_request();
    let resp = test::call_service(&mut app, req).await;

    assert_eq!(resp.status(), http::StatusCode::FORBIDDEN);
}
