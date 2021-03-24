///
/// zian - A minimal pull request build dispatcher for sourcehut's build service
/// Copyright (C) 2021 Austin Ray <austin@austinray.io>
///
/// This program is free software: you can redistribute it and/or modify
/// it under the terms of the GNU Affero General Public License as published
/// by the Free Software Foundation, either version 3 of the License, or
/// (at your option) any later version.
///
/// This program is distributed in the hope that it will be useful,
/// but WITHOUT ANY WARRANTY; without even the implied warranty of
/// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
/// GNU Affero General Public License for more details.
///
/// You should have received a copy of the GNU Affero General Public License
/// along with this program.  If not, see <https://www.gnu.org/licenses/>.
///
use actix_web::{App, HttpServer};
use zian::{
    github_pull_request_webhook, hello_world, AppConfig, GitHubPullRequestChecker,
    IGitHubPullRequestClient,
};

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    // Webhook Control flow
    // ------------
    // 1. Pull request event comes from GitHub
    // 2. Server verifies secret header (X-Hub-Signature-256) from request.
    //    If not, HTTP 400
    // 3. Server checks if project is in allow-list (might not be necessary.)
    //    If not, HTTP 403 - project not supported.
    // 4. Server verifies list of modified files doesn't include:
    //    - `.build.yml`
    //    - `.builds/`
    //    If not, 403 - protected file modified
    // 5. Server verifies pull request has:
    //    - `.build.yml` or
    //    - `.builds/`
    // 6. Infuse build manifests with additional environment variables:
    //    - GITHUB_DELIVERY
    //    - GITHUB_EVENT
    //    - GITHUB_PR_NUMBER
    //    - GITHUB_PR_TITLE
    //    - GITHUB_PR_BODY
    //    - GITHUB_BASE_REPO
    //    - GITHUB_HEAD_REPO
    // 7. Set source to PR branch
    // 8. Submit build to builds.sr.ht using personal access token (temporary measure.)
    HttpServer::new(|| {
        App::new()
            .data(AppConfig {
                github_secret: "example-secret".to_string(),
                pr_checker: Box::new(GitHubPullRequestChecker {
                    github_client: Box::new(IGitHubPullRequestClient {}),
                }),
            })
            .service(hello_world)
            .service(github_pull_request_webhook)
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
