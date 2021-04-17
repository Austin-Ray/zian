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
use zian::GitHubPullRequestWebhook;

use std::fs;

#[test]
fn test_deserialization() {
    let file_name = "tests/resources/github-webhook.json";
    let data = fs::read_to_string(file_name).unwrap();
    let webhook: GitHubPullRequestWebhook = serde_json::from_str(&data).unwrap();

    assert_eq!(webhook.action, "opened");

    let pr = webhook.pull_request;
    assert_eq!(
        pr.url,
        "https://api.github.com/repos/Codertocat/Hello-World/pulls/2"
    );
    assert_eq!(pr.number, 2);
    assert_eq!(pr.title, "Update the README with new information.");
    assert_eq!(
        pr.body,
        "This is a pretty simple change that we need to pull into master."
    );

    let pr_base_repo = pr.base.repo;
    assert_eq!(pr_base_repo.full_name, "Codertocat/Hello-World");

    let pr_head_repo = pr.head.repo;
    assert_eq!(pr_head_repo.full_name, "Codertocat/Hello-World");
}
