"""
Controlled URL Mutation Operators for Robustness Evaluation.
Generates safe syntactic and structural variations of a given URL.
"""
import re
from urllib.parse import urlparse, urlunparse, parse_qs, urlencode
from typing import List, Dict, Any

class UrlMutationGenerator:
    """
    Generates controlled adversarial/syntactic mutations to test model stability.
    """
    
    @staticmethod
    def mutate_add_subdomain(url: str) -> Dict[str, str]:
        """Prepends a benign subdomain label."""
        parsed = urlparse(url)
        if not parsed.netloc:
            return {"variant_name": "Add Subdomain", "url": url}
        new_netloc = f"cdn.{parsed.netloc}"
        new_url = urlunparse((parsed.scheme, new_netloc, parsed.path, parsed.params, parsed.query, parsed.fragment))
        return {
            "variant_name": "Add Subdomain ('cdn.')",
            "description": "Tests if model overreacts to legitimate subdomains.",
            "url": new_url
        }

    @staticmethod
    def mutate_add_query_params(url: str) -> Dict[str, str]:
        """Adds benign query parameters."""
        parsed = urlparse(url)
        query_dict = parse_qs(parsed.query)
        query_dict["utm_source"] = ["newsletter"]
        query_dict["session_id"] = ["88349102"]
        new_query = urlencode(query_dict, doseq=True)
        new_url = urlunparse((parsed.scheme, parsed.netloc, parsed.path, parsed.params, new_query, parsed.fragment))
        return {
            "variant_name": "Add Query Parameters",
            "description": "Tests stability against URL tracking/query expansions.",
            "url": new_url
        }

    @staticmethod
    def mutate_modify_path(url: str) -> Dict[str, str]:
        """Appends directory depth to path."""
        parsed = urlparse(url)
        clean_path = parsed.path.rstrip("/")
        new_path = f"{clean_path}/portal/v2/index.html"
        new_url = urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))
        return {
            "variant_name": "Extend Path Depth",
            "description": "Tests sensitivity to deep path segmentation.",
            "url": new_url
        }

    @staticmethod
    def mutate_insert_hyphen(url: str) -> Dict[str, str]:
        """Inserts hyphen into URL path."""
        parsed = urlparse(url)
        clean_path = parsed.path.rstrip("/")
        new_path = f"{clean_path}-portal" if clean_path else "/app-entry"
        new_url = urlunparse((parsed.scheme, parsed.netloc, new_path, parsed.params, parsed.query, parsed.fragment))
        return {
            "variant_name": "Insert Hyphen in Path",
            "description": "Tests impact of additional hyphen characters.",
            "url": new_url
        }

    @staticmethod
    def mutate_trailing_slash_and_hash(url: str) -> Dict[str, str]:
        """Adds trailing slash and fragment identifier."""
        parsed = urlparse(url)
        clean_path = parsed.path.rstrip("/") + "/"
        new_fragment = "section-main"
        new_url = urlunparse((parsed.scheme, parsed.netloc, clean_path, parsed.params, parsed.query, new_fragment))
        return {
            "variant_name": "Add Trailing Slash & Fragment",
            "description": "Tests impact of standard anchor fragments (#).",
            "url": new_url
        }

    @classmethod
    def generate_all_mutations(cls, original_url: str) -> List[Dict[str, str]]:
        """Generates all 5 controlled variations."""
        url_clean = str(original_url).strip()
        if not url_clean.startswith(("http://", "https://")):
            url_clean = "http://" + url_clean
            
        return [
            cls.mutate_add_subdomain(url_clean),
            cls.mutate_add_query_params(url_clean),
            cls.mutate_modify_path(url_clean),
            cls.mutate_insert_hyphen(url_clean),
            cls.mutate_trailing_slash_and_hash(url_clean)
        ]
