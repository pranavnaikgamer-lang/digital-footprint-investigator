import streamlit as st
import requests
from bs4 import BeautifulSoup
from urllib.parse import urlparse, urljoin

st.set_page_config(
    page_title="Digital Footprint Investigator",
    page_icon="🔍"
)

def get_set_cookie_headers(resp):
    """Return every raw Set-Cookie header (requests merges duplicates otherwise)."""
    try:
        return resp.raw.headers.getlist("Set-Cookie")
    except AttributeError:
        value = resp.headers.get("Set-Cookie")
        return [value] if value else []


def parse_cookie(raw_cookie):
    """Parse a raw Set-Cookie header into its name and security attributes."""
    parts = [p.strip() for p in raw_cookie.split(";") if p.strip()]
    name = parts[0].split("=", 1)[0]

    flags = set()
    samesite = None

    for attr in parts[1:]:
        key, _, value = attr.partition("=")
        key = key.strip().lower()

        if key == "samesite":
            samesite = value.strip().capitalize()
        else:
            flags.add(key)

    return {
        "name": name,
        "secure": "secure" in flags,
        "httponly": "httponly" in flags,
        "samesite": samesite,
    }


st.title("🔍 Digital Footprint Investigator")
st.write("Discover what your publicly accessible online information reveals.")

url = st.text_input("Enter a public webpage URL")

if st.button("Analyze"):

    if not url:
        st.warning("Please enter a URL.")

    else:
        parsed_url = urlparse(url)

        if parsed_url.scheme not in ["http", "https"] or not parsed_url.netloc:
            st.error("Invalid URL.")

        else:
            try:
                # Fetch website
                response = requests.get(
                    url,
                    timeout=10,
                    headers={
                        "User-Agent": "DigitalFootprintInvestigator/1.0"
                    }
                )

                response.raise_for_status()

                soup = BeautifulSoup(response.content, "html.parser")

                st.success("Website fetched successfully!")

                # Website Information
                st.subheader("Website Information")

                st.write("URL:", response.url)
                st.write("Status Code:", response.status_code)

                title = (
                    soup.title.get_text(strip=True)
                    if soup.title else "Not found"
                )

                st.write("Page Title:", title)

                description = soup.find(
                    "meta", attrs={"name": "description"}
                )

                if description:
                    st.write(
                        "Description:",
                        description.get("content", "Not found")
                    )
                else:
                    st.write("Description: Not found")

                # Link Discovery
                st.subheader("🔗 Link Discovery")

                internal_links = []
                external_links = []

                links = soup.find_all("a", href=True)

                for link in links:

                    link_url = urljoin(response.url, link["href"])

                    parsed_link = urlparse(link_url)

                    link_text = link.get_text(strip=True) or "Unnamed link"

                    if parsed_link.scheme not in ["http", "https"]:
                        continue

                    if parsed_link.netloc == urlparse(response.url).netloc:
                        internal_links.append((link_text, link_url))
                    else:
                        external_links.append((link_text, link_url))

                st.write(
                    "Total links:",
                    len(internal_links) + len(external_links)
                )

                col1, col2 = st.columns(2)

                with col1:
                    st.metric("Internal Links", len(internal_links))

                with col2:
                    st.metric("External Links", len(external_links))

                st.write("### Internal Links")

                for text, link in internal_links[:20]:
                    st.markdown(f"[{text}]({link})")

                st.write("### External Links")

                for text, link in external_links[:20]:
                    st.markdown(f"[{text}]({link})")

                # Technology Detection
                st.subheader("🛠️ Website Technology Detection")

                html_content = response.text.lower()

                # Collect JavaScript and CSS resource URLs
                resource_urls = []

                for tag in soup.find_all(["script", "link"]):
                    resource = tag.get("src") or tag.get("href")

                    if resource:
                        resource_urls.append(resource.lower())

                resources = " ".join(resource_urls)

                # WordPress Detection
                wordpress = (
                    "wp-content" in html_content
                    or "wp-includes" in html_content
                    or "wp-json" in html_content
                )

                # React Detection
                react = (
                    "data-reactroot" in html_content
                    or "__react" in html_content
                    or "react-dom" in resources
                    or "react.js" in resources
                )

                # Bootstrap Detection
                bootstrap = (
                    "bootstrap" in resources
                    or "bootstrap.min.css" in html_content
                    or "bootstrap.min.js" in html_content
                )

                # jQuery Detection
                jquery = (
                    "jquery" in resources
                    or "jquery.min.js" in html_content
                    or "window.jquery" in html_content
                    or "jquery(" in html_content
                )

                # Vue.js Detection
                vue = (
                    "vue.js" in resources
                    or "vue.min.js" in resources
                    or "__vue__" in html_content
                    or "v-cloak" in html_content
                )

                # Angular Detection
                angular = (
                    "ng-version" in html_content
                    or "ng-app" in html_content
                    or "angular.js" in resources
                    or "angular.min.js" in resources
                )

                # Display Results
                technologies = {
                    "WordPress": wordpress,
                    "React": react,
                    "Bootstrap": bootstrap,
                    "jQuery": jquery,
                    "Vue.js": vue,
                    "Angular": angular
                }

                for technology, detected in technologies.items():

                    if detected:
                        st.success(f"{technology}: Detected")
                    else:
                        st.info(f"{technology}: Not detected")

                # Security Analysis
                st.subheader("🔒 Security Analysis")

                # Filled in at the end, but displayed at the top
                summary_container = st.container()

                # ---------- HTTPS ----------
                st.write("### HTTPS")

                final_url = urlparse(response.url)
                uses_https = final_url.scheme == "https"

                if uses_https:
                    st.success("The page is served over HTTPS (encrypted connection).")
                else:
                    st.error(
                        "The page is served over plain HTTP. Traffic can be "
                        "read or modified by anyone on the network."
                    )

                if parsed_url.scheme == "http" and uses_https:
                    st.success("The HTTP URL was redirected to HTTPS.")

                # Mixed content: HTTP resources loaded by an HTTPS page
                mixed_content = []

                if uses_https:

                    for tag_name, attr in [
                        ("script", "src"),
                        ("link", "href"),
                        ("img", "src"),
                        ("iframe", "src"),
                    ]:
                        for element in soup.find_all(tag_name, **{attr: True}):
                            if element[attr].strip().lower().startswith("http://"):
                                mixed_content.append(element[attr])

                    if mixed_content:
                        st.warning(
                            f"Mixed content: {len(mixed_content)} resource(s) "
                            "are loaded over insecure HTTP."
                        )
                        with st.expander("Show insecure resources"):
                            for item in mixed_content[:20]:
                                st.code(item)
                    else:
                        st.success("No mixed content found in the HTML.")

                # ---------- Security Headers ----------
                st.write("### Security Headers")

                security_headers = {
                    "Strict-Transport-Security": (
                        "High",
                        "Forces browsers to use HTTPS for future visits (HSTS)."
                    ),
                    "Content-Security-Policy": (
                        "High",
                        "Restricts where scripts, styles and media can load from; mitigates XSS."
                    ),
                    "X-Frame-Options": (
                        "Medium",
                        "Prevents the page from being embedded in frames (clickjacking)."
                    ),
                    "X-Content-Type-Options": (
                        "Medium",
                        "Stops browsers from guessing content types (MIME sniffing)."
                    ),
                    "Referrer-Policy": (
                        "Low",
                        "Controls how much URL information is sent to other sites."
                    ),
                    "Permissions-Policy": (
                        "Low",
                        "Limits access to browser features such as camera and location."
                    ),
                }

                header_rows = []
                present_count = 0
                applicable_headers = 0
                missing_headers = []

                for header, (importance, purpose) in security_headers.items():
                    value = response.headers.get(header)

                    # HSTS only has meaning on HTTPS responses
                    if header == "Strict-Transport-Security" and not uses_https:
                        status = "➖ N/A (not HTTPS)"
                    elif value:
                        status = "✅ Present"
                        present_count += 1
                        applicable_headers += 1
                    else:
                        status = "❌ Missing"
                        applicable_headers += 1
                        missing_headers.append(header)

                    header_rows.append({
                        "Header": header,
                        "Status": status,
                        "Importance": importance,
                        "Value": (value[:80] + "…") if value and len(value) > 80 else (value or "—"),
                        "Purpose": purpose,
                    })

                st.metric(
                    "Security headers present",
                    f"{present_count} / {len(security_headers)}"
                )

                st.dataframe(header_rows, hide_index=True)

                # Headers that leak server information
                leaky_headers = ["Server", "X-Powered-By", "X-AspNet-Version"]
                leaked = {
                    h: response.headers[h]
                    for h in leaky_headers
                    if h in response.headers
                }

                if leaked:
                    st.warning(
                        "Information disclosure: the server reveals technology details."
                    )
                    for h, v in leaked.items():
                        st.write(f"- `{h}: {v}`")
                else:
                    st.success("No server technology disclosure headers found.")

                # ---------- Cookies ----------
                st.write("### Cookie Configuration")

                # Include cookies set during redirects as well as the final response
                raw_cookies = []

                for resp in list(response.history) + [response]:
                    raw_cookies.extend(get_set_cookie_headers(resp))

                cookie_total = 0
                secure_count = 0
                httponly_count = 0
                samesite_count = 0
                issue_count = 0

                if not raw_cookies:
                    st.info("No cookies were set by this page on the initial request.")
                else:
                    cookie_rows = []

                    for raw_cookie in raw_cookies:
                        cookie = parse_cookie(raw_cookie)
                        issues = []

                        cookie_total += 1
                        secure_count += cookie["secure"]
                        httponly_count += cookie["httponly"]
                        samesite_count += cookie["samesite"] is not None

                        if uses_https and not cookie["secure"]:
                            issues.append("Missing Secure")

                        if not cookie["httponly"]:
                            issues.append("Missing HttpOnly")

                        if cookie["samesite"] is None:
                            issues.append("Missing SameSite")
                        elif cookie["samesite"] == "None" and not cookie["secure"]:
                            issues.append("SameSite=None requires Secure")

                        issue_count += len(issues)

                        cookie_rows.append({
                            "Cookie": cookie["name"],
                            "Secure": "✅" if cookie["secure"] else "❌",
                            "HttpOnly": "✅" if cookie["httponly"] else "❌",
                            "SameSite": cookie["samesite"] or "❌ Not set",
                            "Issues": ", ".join(issues) if issues else "None",
                        })

                    col1, col2 = st.columns(2)

                    with col1:
                        st.metric("Cookies found", len(cookie_rows))

                    with col2:
                        st.metric("Configuration issues", issue_count)

                    st.dataframe(cookie_rows, hide_index=True)

                    if issue_count == 0:
                        st.success("All cookies use recommended security attributes.")
                    else:
                        st.warning(
                            "Some cookies are missing recommended attributes. "
                            "HttpOnly is most important for session cookies; "
                            "it is fine for cookies that scripts must read."
                        )

                # ---------- Summary (rendered at the top) ----------
                def ratio_status(count, total):
                    if total == 0:
                        return "➖ N/A"
                    if count == total:
                        return "✅ Pass"
                    if count == 0:
                        return "❌ Fail"
                    return "⚠️ Partial"

                summary_rows = []

                # HTTPS status
                summary_rows.append({
                    "Check": "HTTPS status",
                    "Result": "✅ Pass" if uses_https else "❌ Fail",
                    "Details": "Served over HTTPS" if uses_https else "Served over plain HTTP",
                })

                # Mixed-content detection
                if not uses_https:
                    mixed_result, mixed_detail = "➖ N/A", "Only applies to HTTPS pages"
                elif mixed_content:
                    mixed_result = "⚠️ Found"
                    mixed_detail = f"{len(mixed_content)} insecure resource(s)"
                else:
                    mixed_result, mixed_detail = "✅ Pass", "No mixed content found"

                summary_rows.append({
                    "Check": "Mixed-content detection",
                    "Result": mixed_result,
                    "Details": mixed_detail,
                })

                # Security headers
                header_detail = f"{present_count}/{applicable_headers} present"
                if missing_headers:
                    header_detail += " · Missing: " + ", ".join(missing_headers)

                summary_rows.append({
                    "Check": "Six security headers",
                    "Result": ratio_status(present_count, applicable_headers),
                    "Details": header_detail,
                })

                summary_rows.append({
                    "Check": "Server information disclosure",
                    "Result": "⚠️ Found" if leaked else "✅ Pass",
                    "Details": ", ".join(leaked) if leaked else "No disclosure headers",
                })

                # Cookies
                no_cookies = "No cookies set"

                summary_rows.append({
                    "Check": "Cookie configuration",
                    "Result": (
                        "➖ N/A" if cookie_total == 0
                        else "✅ Pass" if issue_count == 0
                        else "⚠️ Issues"
                    ),
                    "Details": (
                        no_cookies if cookie_total == 0
                        else f"{cookie_total} cookie(s), {issue_count} issue(s)"
                    ),
                })

                for label, count in [
                    ("Secure attribute", secure_count),
                    ("HttpOnly attribute", httponly_count),
                    ("SameSite configuration", samesite_count),
                ]:
                    summary_rows.append({
                        "Check": label,
                        "Result": ratio_status(count, cookie_total),
                        "Details": no_cookies if cookie_total == 0 else f"{count}/{cookie_total} cookies",
                    })

                with summary_container:
                    st.write("### Security Summary")
                    st.dataframe(summary_rows, hide_index=True)

                st.caption(
                    "Note: this analysis only covers cookies and headers returned "
                    "by a single request. Cookies set later by JavaScript are not shown."
                )

            except requests.exceptions.RequestException as e:
                st.error(f"Unable to fetch website: {e}")