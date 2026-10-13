from dataclasses import dataclass
from typing import Any

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry


class SourceFetchError(RuntimeError):
    """A source could not be fetched or decoded."""

    def __init__(
        self,
        message: str,
        *,
        url: str | None = None,
        status_code: int | None = None,
    ) -> None:
        super().__init__(message)
        self.url = url
        self.status_code = status_code


@dataclass(frozen=True)
class SourceResponse:
    request_url: str
    resolved_url: str
    status_code: int
    headers: dict[str, str]
    content: bytes
    encoding: str


class HttpClient:
    def __init__(self, timeout: float = 30.0) -> None:
        self.timeout = timeout
        self.session = requests.Session()
        self.session.headers.update(
            {"Accept": "application/json", "User-Agent": "cwe-kg-phase0/1.0"}
        )
        retry = Retry(
            total=2,
            connect=2,
            read=2,
            status=2,
            backoff_factor=0.5,
            status_forcelist=(429, 500, 502, 503, 504),
            allowed_methods=frozenset({"GET"}),
        )
        self.session.mount("https://", HTTPAdapter(max_retries=retry))
        self.session.mount("http://", HTTPAdapter(max_retries=retry))

    def _get(self, url: str, params: Any = None) -> requests.Response:
        import os
        headers = {}
        github_token = os.environ.get("GITHUB_TOKEN")
        if github_token and "github.com" in url:
            headers["Authorization"] = f"token {github_token}"

        last_exc: Exception | None = None
        for attempt in range(3):
            try:
                response = self.session.get(url, params=params, headers=headers, timeout=self.timeout)
                response.raise_for_status()
                return response
            except requests.RequestException as exc:
                last_exc = exc
                status_code = getattr(getattr(last_exc, "response", None), "status_code", None)
                if status_code == 403 and "github.com" in url:
                    print("\n⚠️ Gặp lỗi GitHub API Rate Limit (HTTP 403).")
                    print("👉 Bạn hãy tạo một Personal Access Token (PAT) trên GitHub (chỉ cần quyền read-only) và thêm vào file `.env` dưới dạng: `GITHUB_TOKEN=your_token` để chạy tiếp nhé!\n")
                if attempt < 2:
                    import time
                    time.sleep(1.0 * (attempt + 1))
        status_code = getattr(getattr(last_exc, "response", None), "status_code", None)
        raise SourceFetchError(
            f"failed to fetch {url}: {last_exc}",
            url=url,
            status_code=status_code,
        ) from last_exc

    def get_json(self, url: str, params: Any = None) -> Any:
        response = self._get(url, params=params)
        try:
            return response.json()
        except requests.JSONDecodeError as exc:
            raise SourceFetchError(f"invalid JSON from {url}: {exc}") from exc

    def fetch(self, url: str, params: Any = None) -> SourceResponse:
        response = self._get(url, params=params)
        return SourceResponse(
            request_url=str(response.request.url),
            resolved_url=str(response.url),
            status_code=response.status_code,
            headers=dict(response.headers),
            content=response.content,
            encoding=(
                response.encoding
                or response.apparent_encoding
                or "utf-8"
            ),
        )

    def get_bytes_and_text(self, url: str) -> tuple[bytes, str]:
        response = self._get(url)
        response.encoding = response.encoding or "utf-8"
        return response.content, response.text

    def get_text(self, url: str) -> str:
        _bytes, text = self.get_bytes_and_text(url)
        return text

    def close(self) -> None:
        self.session.close()
