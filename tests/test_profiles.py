"""Tests for C2 profile parsers."""

from pathlib import Path

import pytest

from infraguard.profiles.cobalt_strike import CobaltStrikeParser, parse_cobalt_strike_file
from infraguard.profiles.models import C2Profile, Transform
from infraguard.profiles.mythic import MythicHTTPParser, parse_mythic_file
from infraguard.profiles.sliver import SliverParser, parse_sliver_file
from infraguard.profiles.transforms import TransformChain

# ── Cobalt Strike parser ──────────────────────────────────────────────

CS_PROFILE = Path("examples/jquery-c2.3.14.profile")
CS_JSON = Path("examples/jquery-c2.3.14.profile.json")
MYTHIC_JSON = Path("examples/mythic-httpx.json")
SLIVER_JSON = Path("examples/sliver.json")


@pytest.mark.skipif(not CS_PROFILE.exists(), reason="CS profile not found")
class TestCobaltStrikeParser:
    def test_parse_name(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert profile.name == "jQuery Profile"

    def test_parse_useragent(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert "Trident" in profile.useragent

    def test_parse_sleeptime(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert profile.sleeptime == 60000

    def test_parse_jitter(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert profile.jitter == 37

    def test_parse_http_get(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert profile.http_get is not None
        assert profile.http_get.verb == "GET"
        assert "/jquery-3.3.1.min.js" in profile.http_get.uris

    def test_parse_http_post(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert profile.http_post is not None
        assert profile.http_post.verb == "POST"

    def test_parse_http_stager(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        assert profile.http_stager is not None
        assert len(profile.http_stager.uris) == 2

    def test_parse_client_headers(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        headers = profile.http_get.client.headers
        assert "Accept" in headers
        assert "Host" in headers
        assert headers["Host"] == "code.jquery.com"

    def test_parse_metadata_location(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        msg = profile.http_get.client.message
        assert msg is not None
        assert msg.location == "cookie"
        assert msg.name == "__cfduid"

    def test_parse_transforms(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        transforms = profile.http_get.client.transforms
        assert len(transforms) >= 1
        actions = [t.action for t in transforms]
        assert "base64url" in actions

    def test_all_uris(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        uris = profile.all_uris()
        assert len(uris) >= 4

    def test_to_json_roundtrip(self):
        profile = parse_cobalt_strike_file(CS_PROFILE)
        json_str = profile.to_json()
        restored = C2Profile.from_json(json_str)
        assert restored.name == profile.name
        assert len(restored.all_uris()) == len(profile.all_uris())


# ── Mythic parser ─────────────────────────────────────────────────────

@pytest.mark.skipif(not MYTHIC_JSON.exists(), reason="Mythic profile not found")
class TestMythicParser:
    def test_parse_name(self):
        profile = parse_mythic_file(MYTHIC_JSON)
        assert "Mythic" in profile.name or "CDN" in profile.name

    def test_parse_http_get(self):
        profile = parse_mythic_file(MYTHIC_JSON)
        assert profile.http_get is not None
        assert profile.http_get.verb == "GET"

    def test_parse_http_post(self):
        profile = parse_mythic_file(MYTHIC_JSON)
        assert profile.http_post is not None
        assert profile.http_post.verb == "POST"

    def test_parse_uris(self):
        profile = parse_mythic_file(MYTHIC_JSON)
        uris = profile.all_uris()
        assert len(uris) >= 2


# ── Transform chain ───────────────────────────────────────────────────

class TestTransformChain:
    def test_base64_roundtrip(self):
        chain = TransformChain([Transform(action="base64")])
        data = b"hello world"
        encoded = chain.encode(data)
        decoded = chain.decode(encoded)
        assert decoded == data

    def test_base64url_roundtrip(self):
        chain = TransformChain([Transform(action="base64url")])
        data = b"test data with special chars: +/="
        encoded = chain.encode(data)
        decoded = chain.decode(encoded)
        assert decoded == data

    def test_prepend_append(self):
        chain = TransformChain([
            Transform(action="prepend", value="PREFIX_"),
            Transform(action="append", value="_SUFFIX"),
        ])
        data = b"data"
        encoded = chain.encode(data)
        assert encoded == b"PREFIX_data_SUFFIX"
        decoded = chain.decode(encoded)
        assert decoded == data

    def test_validate_prepend_append(self):
        chain = TransformChain([
            Transform(action="prepend", value="__cfduid="),
        ])
        assert chain.validate_prepend_append(b"__cfduid=abc123")
        assert not chain.validate_prepend_append(b"othercookie=abc123")

    def test_netbios_roundtrip(self):
        chain = TransformChain([Transform(action="netbios")])
        data = b"\x41\x42"
        encoded = chain.encode(data)
        decoded = chain.decode(encoded)
        assert decoded == data

    def test_mask_roundtrip(self):
        chain = TransformChain([Transform(action="mask")])
        data = b"secret beacon data"
        encoded = chain.encode(data)
        assert encoded != data
        decoded = chain.decode(encoded)
        assert decoded == data


# ── Sliver parser ─────────────────────────────────────────────────────

# As returned by the teamserver's GetHTTPC2ProfileByName RPC: protobuf-JSON,
# so .proto field names rather than the ones `c2profile export` writes.
SLIVER_API_JSON = """{
  "ID": "ff585828-8e07-4fc1-a1b5-05a6c378b108",
  "Created": "1792418590",
  "Name": "default",
  "ServerConfig": {
    "Headers": [
      {"Method": "GET", "Name": "Cache-Control", "Value": "no-store", "Probability": 100}
    ],
    "Cookies": [{"Name": "JSESSIONID"}, {"Name": "PHPSESSID"}]
  },
  "ImplantConfig": {
    "UserAgent": "",
    "ChromeBaseVersion": 106,
    "extensions": ["js", "", "php"],
    "PathSegments": [
      {"IsFile": true, "Value": "bootstrap"},
      {"IsFile": true, "Value": "jquery.min"},
      {"IsFile": false, "Value": "assets"},
      {"IsFile": false, "Value": "static"}
    ],
    "NonceMode": "UrlParam",
    "NonceQueryLength": 1
  }
}"""

# The format `c2profile export` writes: unified extensions/files/paths.
SLIVER_EXPORT_JSON = """{
  "implant_config": {
    "user_agent": "",
    "extensions": ["js", "php"],
    "files": ["bootstrap"],
    "paths": ["assets"]
  },
  "server_config": {
    "headers": [{"name": "Server", "value": "nginx", "probability": 100}],
    "cookies": ["PHPSESSID"]
  }
}"""


class TestSliverApiShapedProfile:
    """Profiles taken from the gRPC API, not from `c2profile export`."""

    def test_parses_into_uris(self):
        profile = SliverParser().parse(SLIVER_API_JSON)
        assert profile.http_get is not None
        assert profile.http_post is not None
        assert profile.all_uris()

    def test_path_segments_split_by_isfile(self):
        profile = SliverParser().parse(SLIVER_API_JSON)
        uris = set(profile.all_uris())
        # paths come from IsFile=false, files from IsFile=true
        assert "/assets/bootstrap.js" in uris
        assert "/static/jquery.min.php" in uris
        # an empty extension means no suffix at all
        assert "/assets/bootstrap" in uris

    def test_cookies_are_unwrapped(self):
        profile = SliverParser().parse(SLIVER_API_JSON)
        assert profile.global_options["cookies"] == "JSESSIONID,PHPSESSID"

    def test_server_headers_survive(self):
        profile = SliverParser().parse(SLIVER_API_JSON)
        assert profile.http_get.server.headers["Cache-Control"] == "no-store"


class TestSliverExportedProfile:
    def test_unified_keys_still_parse(self):
        profile = SliverParser().parse(SLIVER_EXPORT_JSON)
        uris = set(profile.all_uris())
        assert "/assets/bootstrap.js" in uris
        assert "/assets/bootstrap.php" in uris
        assert profile.global_options["cookies"] == "PHPSESSID"


@pytest.mark.skipif(not SLIVER_JSON.exists(), reason="Sliver example not found")
class TestSliverStageSpecificProfile:
    def test_example_still_parses(self):
        profile = parse_sliver_file(SLIVER_JSON)
        assert profile.http_get is not None
        assert profile.http_post is not None


class TestSliverProfileErrors:
    def test_unrecognised_shape_raises(self):
        # A Sliver *implant* config, not an HTTP C2 profile - an easy mix-up.
        with pytest.raises(ValueError, match="unrecognised Sliver profile"):
            SliverParser().parse('{"GOOS": "linux", "GOARCH": "amd64"}')

    def test_profile_with_no_uris_raises(self):
        # Parsed fine but generates nothing, so it would block every request.
        with pytest.raises(ValueError, match="no URIs"):
            SliverParser().parse('{"implant_config": {}, "server_config": {}}')
