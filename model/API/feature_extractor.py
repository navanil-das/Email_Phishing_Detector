import socket
import tldextract
from .network_feature import (
    fetch_page,
    double_slash_redirecting,
    submitting_to_email,
    iframe,
    on_mouseover,
    right_click,
    pop_up_window,
    request_url,
    redirect_count,
    dns_record,
    age_of_domain,
    port_feature,
    https_token,
    abnormal_url,
    url_of_anchor,
    links_in_tags,
    sfh_feature
)

def having_ip_address(url):
    try:
        socket.inet_aton(url.split("//")[-1].split("/")[0])
        return -1
    except:
        return 1

def url_length(url):
    return -1 if len(url) > 75 else 1

def having_at_symbol(url):
    return -1 if "@" in url else 1

def shortining_service(url):
    services = ["bit.ly", "tinyurl.com", "goo.gl", "t.co"]
    return -1 if any(s in url for s in services) else 1

def prefix_suffix(domain):
    return -1 if "-" in domain else 1

def having_sub_domain(url):
    ext = tldextract.extract(url)
    return -1 if ext.subdomain.count(".") >= 1 and ext.subdomain != "" else 1

def ssl_final_state(url):
    return 1 if url.startswith("https://") else -1

def extract_features(url: str):
    ext = tldextract.extract(url)
    domain = f"{ext.domain}.{ext.suffix}"

    html, final_url, history = fetch_page(url)
    final_url = final_url or url

    features = [
        having_ip_address(url),
        url_length(url),
        shortining_service(url),
        having_at_symbol(url),
        double_slash_redirecting(final_url),
        prefix_suffix(domain),
        having_sub_domain(url),
        ssl_final_state(final_url),
        1,  # Domain_registeration_length (still TODO)
        1,  # Favicon (TODO)
        port_feature(final_url),
        https_token(final_url),
        request_url(final_url, html),
        url_of_anchor(final_url, html),
        links_in_tags(final_url, html),
        sfh_feature(final_url, html),
        submitting_to_email(html),
        abnormal_url(url, final_url),
        redirect_count(history),
        on_mouseover(html),
        right_click(html),
        pop_up_window(html),
        iframe(html),
        age_of_domain(final_url),
        dns_record(final_url),
        1,  # web_traffic (TODO)
        1,  # Page_Rank (TODO)
        1,  # Google_Index (TODO)
        1,  # Links_pointing_to_page (TODO)
        1   # Statistical_report (TODO)
    ]

    return features
