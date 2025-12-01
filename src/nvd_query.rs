use anyhow::Result;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct NvdResponse {
    vulnerabilities: Option<Vec<Vulnerability>>,
}

#[derive(Debug, Deserialize)]
struct Vulnerability {
    cve: CveData,
}

#[derive(Debug, Deserialize)]
struct CveData {
    id: String,
    //published: String,
    descriptions: Vec<Description>,
    metrics: Option<Metrics>
}

#[derive(Debug, Deserialize)]
struct Description {
    value: String,
}

#[derive(Debug, Deserialize)]
struct Metrics {
    // 2. The API returns a list of metrics (e.g., from different sources like NVD or CNA)
    #[serde(rename = "cvssMetricV31")]
    cvss_metric_v31: Option<Vec<CvssMetricV31>>,
}

#[derive(Debug, Deserialize)]
struct CvssMetricV31 {
    #[serde(rename = "cvssData")]
    cvss_data: CvssData,
}

#[derive(Debug, Deserialize)]
struct CvssData {
    // 3. We finally reach the actual data strings/floats
    #[serde(rename = "baseScore")]
    base_score: f64,
    #[serde(rename = "vectorString")]
    vector_string: String,
}

pub async fn search_vulns_nvd(query: &str) -> Result<Vec<String>> {
    let url = format!(
        "https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={}",
        query
    );

    // let resp: NvdResponse = reqwest::get(&url).await?.json().await?;
    // println!("{:?}", resp);
    let response = reqwest::get(&url).await?;
    let text = response.text().await?;

    let resp: NvdResponse = match serde_json::from_str(&text) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("\n--- NVD API ERROR ---");
            eprintln!("URL: {}", url);
            eprintln!("Raw body:\n{}", text);
            eprintln!("JSON ERROR: {}", e);
            return Err(e.into());
        }
    };

    let Some(vulns) = resp.vulnerabilities else {
        return Ok(Vec::new());
    };

    let mut list = Vec::new();
    
    for v in vulns {
        let desc = v.cve.descriptions.get(0).map(|d| d.value.clone()).unwrap_or_default();
        let score_str = if let Some(metrics) = &v.cve.metrics {
            if let Some(v31) = &metrics.cvss_metric_v31 {
                if let Some(first_metric) = v31.get(0) {
                    format!("Base score: {}\n\tVectorString: {}", first_metric.cvss_data.base_score, first_metric.cvss_data.vector_string)
                } else {
                    "No CVSS Score".to_string()
                }
            } else {
                "No CVSS Score".to_string()
            }
        } else {
            "No CVSS Score".to_string()
        };

        list.push(format!(
            "{} - {} \n\t {}",
            v.cve.id,
            desc,
            score_str
        ));
    }

    Ok(list)
}
