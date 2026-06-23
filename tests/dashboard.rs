mod common;
use anyhow::Result;
use chrono::{Duration, Utc};
use serde_json::json;

#[tokio::test]
async fn test_dashboard() -> Result<()> {
    let app = common::app();
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    app.seed_database(100)?;

    let project_id = "public-project";
    let api_prefix = format!("/api/dashboard/project/{project_id}");
    let stats_path = format!("{api_prefix}/stats");
    let graph_path = format!("{api_prefix}/graph");
    let dimension_path = format!("{api_prefix}/dimension");

    let start_date = (Utc::now() - Duration::days(365)).to_rfc3339();
    let end_date = Utc::now().to_rfc3339();

    let stats_requests = [
        json!({"range":{"start": start_date ,"end": end_date},"filters":[]}),
        json!({"range":{"start": start_date ,"end": end_date},"filters":[{"dimension":"fqdn","filterType":"equal","value":"example.org"},{"dimension":"url","filterType":"equal","value":"example.org/contact"},{"dimension":"referrer","filterType":"equal","value":"liwan.dev"},{"dimension":"country","filterType":"equal","value":"AU"},{"dimension":"city","filterType":"equal","value":"Sydney"},{"dimension":"platform","filterType":"equal","value":"iOS"},{"dimension":"browser","filterType":"equal","value":"Safari"}]}),
    ];

    let graph_requests = [
        json!({"range":{"start": start_date ,"end": end_date},"metric":"views","interval":"day","timezone":"UTC","filters":[]}),
        json!({"range":{"start": start_date ,"end": end_date},"metric":"views","interval":"day","timezone":"UTC","filters":[{"dimension":"fqdn","filterType":"equal","value":"example.org"},{"dimension":"url","filterType":"equal","value":"example.org/contact"},{"dimension":"referrer","filterType":"equal","value":"liwan.dev"},{"dimension":"country","filterType":"equal","value":"AU"},{"dimension":"city","filterType":"equal","value":"Sydney"},{"dimension":"platform","filterType":"equal","value":"iOS"},{"dimension":"browser","filterType":"equal","value":"Safari"}]}),
    ];

    let dimensions_requests = [
        json!({"dimension":"country","filters":[],"metric":"views","range":{"start": start_date ,"end": end_date}}),
        json!({"dimension":"url","filters":[{"dimension":"fqdn","filterType":"equal","value":"example.org"},{"dimension":"url","filterType":"equal","value":"example.org/contact"},{"dimension":"referrer","filterType":"equal","value":"liwan.dev"},{"dimension":"country","filterType":"equal","value":"AU"},{"dimension":"city","filterType":"equal","value":"Sydney"},{"dimension":"platform","filterType":"equal","value":"iOS"},{"dimension":"browser","filterType":"equal","value":"Safari"},{"dimension":"mobile","filterType":"is_true"}],"metric":"views","range":{"start": start_date ,"end": end_date}}),
        json!({"dimension":"city","filters":[{"dimension":"fqdn","filterType":"equal","value":"example.org"},{"dimension":"url","filterType":"equal","value":"example.org/contact"},{"dimension":"referrer","filterType":"equal","value":"liwan.dev"},{"dimension":"country","filterType":"equal","value":"AU"},{"dimension":"city","filterType":"equal","value":"Sydney"},{"dimension":"platform","filterType":"equal","value":"iOS"},{"dimension":"browser","filterType":"equal","value":"Safari"},{"dimension":"mobile","filterType":"is_true"}],"metric":"views","range":{"start": start_date ,"end": end_date}}),
        json!({"dimension":"browser","filters":[{"dimension":"fqdn","filterType":"equal","value":"example.org"},{"dimension":"url","filterType":"equal","value":"example.org/contact"},{"dimension":"referrer","filterType":"equal","value":"liwan.dev"},{"dimension":"country","filterType":"equal","value":"AU"},{"dimension":"city","filterType":"equal","value":"Sydney"},{"dimension":"platform","filterType":"equal","value":"iOS"},{"dimension":"browser","filterType":"equal","value":"Safari"},{"dimension":"mobile","filterType":"is_true"}],"metric":"views","range":{"start": start_date ,"end": end_date}}),
        json!({"dimension":"screen_width","filters":[],"metric":"views","range":{"start": start_date ,"end": end_date}}),
        json!({"dimension":"url","filters":[{"dimension":"screen_width","filterType":"equal","value":"xs"}],"metric":"views","range":{"start": start_date ,"end": end_date}}),
    ];

    for request in stats_requests.iter() {
        let res = client.post(&stats_path, request.clone()).await;
        res.assert_status_success();
    }

    for request in graph_requests.iter() {
        let res = client.post(&graph_path, request.clone()).await;
        res.assert_status_success();
    }

    for request in dimensions_requests.iter() {
        let res = client.post(&dimension_path, request.clone()).await;
        res.assert_status_success();
    }

    Ok(())
}

#[tokio::test]
async fn test_entity_filter() -> Result<()> {
    let app = common::app();
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    app.seed_database(100)?;

    let stats_path = "/api/dashboard/project/public-project/stats";
    let start = (Utc::now() - Duration::days(365)).to_rfc3339();
    let end = Utc::now().to_rfc3339();

    // Unfiltered baseline.
    let base = client.post(stats_path, json!({"range":{"start":start,"end":end},"filters":[]})).await;
    base.assert_status_success();
    let base_views = base.json::<serde_json::Value>()["stats"]["totalViews"].clone();

    // Valid entity filter. public-project only contains entity-1, so scoping to it
    // must return the same totals as the unfiltered query.
    let valid = client
        .post(
            stats_path,
            json!({"range":{"start":start,"end":end},"filters":[
                {"dimension":"entity_id","filterType":"equal","value":"entity-1"}
            ]}),
        )
        .await;
    valid.assert_status_success();
    assert_eq!(valid.json::<serde_json::Value>()["stats"]["totalViews"], base_views);

    // An entity that is not a member of public-project must be rejected.
    let invalid = client
        .post(
            stats_path,
            json!({"range":{"start":start,"end":end},"filters":[
                {"dimension":"entity_id","filterType":"equal","value":"entity-2"}
            ]}),
        )
        .await;
    invalid.assert_status_bad_request();

    Ok(())
}

#[tokio::test]
async fn test_custom_events() -> Result<()> {
    let app = common::app();
    let (tx, _rx) = common::events();
    let client = common::TestClient::new(app.clone(), tx);

    app.seed_database(200)?;

    let api_prefix = "/api/dashboard/project/public-project";
    let start = (Utc::now() - Duration::days(365)).to_rfc3339();
    let end = Utc::now().to_rfc3339();

    // The Events breakdown lists custom events and excludes the implicit pageview scope.
    let dim = client
        .post(
            &format!("{api_prefix}/dimension"),
            json!({"dimension":"event","filters":[],"metric":"views","range":{"start":start,"end":end}}),
        )
        .await;
    dim.assert_status_success();
    let body = dim.json::<serde_json::Value>();
    let names: Vec<String> = body["data"]
        .as_array()
        .expect("data array")
        .iter()
        .map(|row| row["dimensionValue"].as_str().expect("dimensionValue").to_string())
        .collect();
    assert!(names.iter().any(|n| n == "signup"), "expected a signup event, got {names:?}");
    assert!(!names.iter().any(|n| n == "pageview"), "events card must exclude pageview");

    // Baseline: the default pageview scope reports session metrics, so a NULL below proves scope-driven nulling rather than empty data.
    let pageview =
        client.post(&format!("{api_prefix}/stats"), json!({"range":{"start":start,"end":end},"filters":[]})).await;
    pageview.assert_status_success();
    assert!(!pageview.json::<serde_json::Value>()["stats"]["bounceRate"].is_null());

    // Scoping stats to a custom event nulls the session metrics.
    let stats = client
        .post(
            &format!("{api_prefix}/stats"),
            json!({"range":{"start":start,"end":end},"filters":[
                {"dimension":"event","filterType":"equal","value":"signup"}
            ]}),
        )
        .await;
    stats.assert_status_success();
    let body = stats.json::<serde_json::Value>();
    assert!(body["stats"]["totalViews"].as_u64().expect("totalViews") > 0);
    assert!(body["stats"]["bounceRate"].is_null());
    assert!(body["stats"]["avgTimeOnSite"].is_null());

    // Session metrics are rejected under an event scope on the graph endpoint.
    let graph = client
        .post(
            &format!("{api_prefix}/graph"),
            json!({"range":{"start":start,"end":end},"metric":"bounce_rate","interval":"day","timezone":"UTC","filters":[
                {"dimension":"event","filterType":"equal","value":"signup"}
            ]}),
        )
        .await;
    graph.assert_status_bad_request();

    Ok(())
}
