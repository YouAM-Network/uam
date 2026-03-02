"""Integration tests for bundled avatar libraries.

Tests the bots and crustaceans SVG asset libraries end-to-end using the
real bundled assets -- no mocks. Verifies loading, discovery, generation,
determinism, performance, cache behavior, 5-component counts, currentColor
usage, and visual distinctness across addresses.
"""

from __future__ import annotations

import json
import time
from pathlib import Path

import pytest

from uam.cards.avatar_engine import (
    clear_library_cache,
    discover_libraries,
    generate_avatar,
    load_library,
)

# Path to bundled libraries in development layout
AVATARS_PATH = Path(__file__).parent.parent.parent / "src" / "uam" / "cards" / "avatars"

# Crustaceans is a relay-specific library, not shipped in the public package
_has_crustaceans = (AVATARS_PATH / "crustaceans" / "manifest.json").exists()
skip_no_crustaceans = pytest.mark.skipif(
    not _has_crustaceans, reason="crustaceans library not bundled (relay-specific)"
)


@pytest.fixture(autouse=True)
def _clear_cache() -> None:
    """Clear library cache before each test for isolation."""
    clear_library_cache()


# ---------------------------------------------------------------------------
# TestBotsLibrary
# ---------------------------------------------------------------------------


class TestBotsLibrary:
    """Tests for the bundled mecha bots asset library."""

    def test_bots_library_loads(self) -> None:
        """load_library succeeds and returns library with name='bots'."""
        lib = load_library(AVATARS_PATH / "bots")
        assert lib.name == "bots"
        assert lib.version == "2.0.0"
        assert lib.width == 200
        assert lib.height == 200
        assert lib.shape == "circle"

    def test_bots_manifest_has_six_layers(self) -> None:
        """Bots library has exactly 6 layers."""
        lib = load_library(AVATARS_PATH / "bots")
        assert len(lib.layers) == 6

    def test_bots_layer_component_counts(self) -> None:
        """Each bots layer has the expected number of components."""
        lib = load_library(AVATARS_PATH / "bots")
        expected = {
            "ears": 5,
            "chassis-base": 4,
            "decals": 4,
            "chassis-highlight": 4,
            "mouth": 5,
            "visor": 4,
        }
        for layer in lib.layers:
            name = layer["name"]
            assert name in expected, f"Unexpected layer '{name}'"
            assert len(layer["components"]) == expected[name], (
                f"Layer '{name}' has {len(layer['components'])} components, expected {expected[name]}"
            )

    def test_bots_chassis_highlight_linked_to_chassis_base(self) -> None:
        """chassis-highlight layer has linked_to pointing at chassis-base."""
        lib = load_library(AVATARS_PATH / "bots")
        highlight_layer = next(l for l in lib.layers if l["name"] == "chassis-highlight")
        assert highlight_layer.get("linked_to") == "chassis-base"

    def test_bots_generate_avatar_returns_png(self) -> None:
        """generate_avatar with 'bots' returns bytes starting with PNG magic."""
        png = generate_avatar("test::relay", "bots", library_path=AVATARS_PATH)
        assert isinstance(png, bytes)
        assert png[:8] == b"\x89PNG\r\n\x1a\n"
        assert len(png) > 100  # Non-trivial PNG

    def test_bots_deterministic_100_times(self) -> None:
        """100 calls with same address produce byte-identical output."""
        first = generate_avatar("det::bots.test", "bots", library_path=AVATARS_PATH)
        for _ in range(99):
            result = generate_avatar("det::bots.test", "bots", library_path=AVATARS_PATH)
            assert result == first

    def test_bots_has_42_palettes(self) -> None:
        """Bots library has 42 palettes (7 chassis colors x 6 glow colors) with colors dict."""
        lib = load_library(AVATARS_PATH / "bots")
        assert len(lib.palettes) == 42
        for palette in lib.palettes:
            assert "colors" in palette, f"Palette '{palette['name']}' missing 'colors' dict"
            colors = palette["colors"]
            for key in ("base", "shadow", "highlight", "outline", "glow_core", "glow_aura"):
                assert key in colors, f"Palette '{palette['name']}' missing color key '{key}'"

    def test_bots_color_token_layers_contain_tokens(self) -> None:
        """Chassis, ears, and highlight SVGs contain TOKEN_ color placeholders."""
        token_layers = {"ears", "chassis-base", "chassis-highlight"}
        manifest_path = AVATARS_PATH / "bots" / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        lib_dir = AVATARS_PATH / "bots"
        for layer in manifest["layers"]:
            if layer["name"] not in token_layers:
                continue
            for svg_name in layer["components"]:
                svg_path = lib_dir / svg_name
                content = svg_path.read_text()
                assert "TOKEN_" in content or svg_name == "ears-none.svg", (
                    f"SVG '{svg_name}' in layer '{layer['name']}' missing TOKEN_ color placeholders"
                )

    def test_bots_visor_svgs_contain_glow_tokens(self) -> None:
        """Visor SVGs contain TOKEN_GLOW_CORE and TOKEN_GLOW_AURA placeholders."""
        manifest_path = AVATARS_PATH / "bots" / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        lib_dir = AVATARS_PATH / "bots"
        for layer in manifest["layers"]:
            if layer["name"] != "visor":
                continue
            for svg_name in layer["components"]:
                svg_path = lib_dir / svg_name
                content = svg_path.read_text()
                assert "TOKEN_GLOW_CORE" in content, (
                    f"Visor '{svg_name}' missing TOKEN_GLOW_CORE"
                )
                assert "TOKEN_GLOW_AURA" in content, (
                    f"Visor '{svg_name}' missing TOKEN_GLOW_AURA"
                )


# ---------------------------------------------------------------------------
# TestCrustaceansLibrary
# ---------------------------------------------------------------------------


@skip_no_crustaceans
class TestCrustaceansLibrary:
    """Tests for the bundled crustaceans asset library."""

    def test_crustaceans_library_loads(self) -> None:
        """load_library succeeds for crustaceans."""
        lib = load_library(AVATARS_PATH / "crustaceans")
        assert lib.name == "crustaceans"
        assert lib.version == "2.1.0"

    def test_crustaceans_manifest_has_eight_layers(self) -> None:
        """Crustaceans library has exactly 8 layers."""
        lib = load_library(AVATARS_PATH / "crustaceans")
        assert len(lib.layers) == 8

    def test_crustaceans_layer_component_counts(self) -> None:
        """Each crustaceans layer has the expected number of components."""
        lib = load_library(AVATARS_PATH / "crustaceans")
        expected = {
            "body-base": 1,
            "antennae": 3,
            "claws": 3,
            "body-carapace": 1,
            "pattern": 7,
            "hair": 32,
            "eyes": 9,
            "mouth": 8,
        }
        for layer in lib.layers:
            name = layer["name"]
            assert name in expected, f"Unexpected layer '{name}'"
            assert len(layer["components"]) == expected[name], (
                f"Layer '{name}' has {len(layer['components'])} components, expected {expected[name]}"
            )

    def test_crustaceans_generate_avatar_returns_png(self) -> None:
        """generate_avatar with 'crustaceans' returns valid PNG bytes."""
        png = generate_avatar("test::relay", "crustaceans", library_path=AVATARS_PATH)
        assert isinstance(png, bytes)
        assert png[:8] == b"\x89PNG\r\n\x1a\n"
        assert len(png) > 100

    def test_crustaceans_deterministic_100_times(self) -> None:
        """100 calls with same address produce byte-identical output."""
        first = generate_avatar(
            "det::crust.test", "crustaceans", library_path=AVATARS_PATH
        )
        for _ in range(99):
            result = generate_avatar(
                "det::crust.test", "crustaceans", library_path=AVATARS_PATH
            )
            assert result == first

    def test_crustaceans_color_token_layers_contain_tokens(self) -> None:
        """Body, antennae, claws, and carapace SVGs contain TOKEN_ color placeholders."""
        token_layers = {"body-base", "antennae", "claws", "body-carapace"}
        manifest_path = AVATARS_PATH / "crustaceans" / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        lib_dir = AVATARS_PATH / "crustaceans"
        for layer in manifest["layers"]:
            if layer["name"] not in token_layers:
                continue
            for svg_name in layer["components"]:
                svg_path = lib_dir / svg_name
                content = svg_path.read_text()
                assert "TOKEN_BASE" in content or "TOKEN_OUTLINE" in content, (
                    f"SVG '{svg_name}' in layer '{layer['name']}' missing TOKEN_ color placeholders"
                )

    def test_crustaceans_has_twelve_palettes(self) -> None:
        """Crustaceans library has 12 body-color palettes with colors dict."""
        lib = load_library(AVATARS_PATH / "crustaceans")
        assert len(lib.palettes) == 12
        for palette in lib.palettes:
            assert "colors" in palette, f"Palette '{palette['name']}' missing 'colors' dict"
            colors = palette["colors"]
            for key in ("base", "shadow", "dark", "outline"):
                assert key in colors, f"Palette '{palette['name']}' missing color key '{key}'"


# ---------------------------------------------------------------------------
# TestLibraryDiscovery
# ---------------------------------------------------------------------------


class TestLibraryDiscovery:
    """Tests for discovering and using bundled libraries."""

    def test_discover_finds_bots_library(self) -> None:
        """discover_libraries always includes the default 'bots' library."""
        libs = discover_libraries(AVATARS_PATH)
        assert "bots" in libs

    @skip_no_crustaceans
    def test_discover_finds_crustaceans_library(self) -> None:
        """discover_libraries includes 'crustaceans' when present."""
        libs = discover_libraries(AVATARS_PATH)
        assert "crustaceans" in libs

    @skip_no_crustaceans
    def test_different_styles_produce_different_avatars(self) -> None:
        """Same address with different styles produces different PNG bytes."""
        bots_png = generate_avatar("same::addr", "bots", library_path=AVATARS_PATH)
        crust_png = generate_avatar(
            "same::addr", "crustaceans", library_path=AVATARS_PATH
        )
        assert bots_png != crust_png

    def test_custom_library_path(self, tmp_path: Path) -> None:
        """A minimal custom library in tmp_path is discoverable via library_path."""
        # Create a minimal library
        lib_dir = tmp_path / "custom"
        lib_dir.mkdir()

        manifest = {
            "name": "custom",
            "version": "1.0.0",
            "width": 200,
            "height": 200,
            "layers": [
                {
                    "name": "bg",
                    "required": True,
                    "components": ["bg.svg"],
                },
            ],
            "palettes": [
                {
                    "name": "default",
                    "background": "#000",
                    "accent": "#fff",
                    "colors": [],
                },
            ],
        }
        (lib_dir / "manifest.json").write_text(json.dumps(manifest))
        (lib_dir / "bg.svg").write_text(
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200">'
            '<rect width="200" height="200" fill="currentColor"/>'
            "</svg>"
        )

        png = generate_avatar("custom::test", "custom", library_path=tmp_path)
        assert png[:8] == b"\x89PNG\r\n\x1a\n"


# ---------------------------------------------------------------------------
# TestVisualDistinctness
# ---------------------------------------------------------------------------


class TestVisualDistinctness:
    """Tests that expanded variant pool produces visually distinct results."""

    def test_visual_distinctness_different_addresses(self) -> None:
        """Generate avatars for 10 different addresses and verify at least 8 produce unique PNG bytes."""
        addresses = [
            f"distinct-{i}::relay.test" for i in range(10)
        ]
        pngs = []
        for addr in addresses:
            png = generate_avatar(addr, "bots", library_path=AVATARS_PATH)
            pngs.append(png)

        unique_pngs = set(pngs)
        assert len(unique_pngs) >= 8, (
            f"Only {len(unique_pngs)} unique avatars from 10 addresses, expected at least 8"
        )


# ---------------------------------------------------------------------------
# TestPerformance
# ---------------------------------------------------------------------------


class TestPerformance:
    """Performance benchmarks for avatar generation."""

    def test_generation_under_200ms(self) -> None:
        """Average generation time for 200x200 is under 200ms over 10 runs."""
        # Warm-up run (populates cache)
        generate_avatar("perf::test", "bots", 200, library_path=AVATARS_PATH)

        times = []
        for _ in range(10):
            start = time.perf_counter()
            generate_avatar("perf::test", "bots", 200, library_path=AVATARS_PATH)
            elapsed = time.perf_counter() - start
            times.append(elapsed)

        avg_ms = (sum(times) / len(times)) * 1000
        assert avg_ms < 200, f"Average generation took {avg_ms:.1f}ms, expected < 200ms"

    def test_size_variants(self) -> None:
        """Generation at 100, 200, 400px all produce valid PNGs."""
        times_200 = []
        times_400 = []

        for size in (100, 200, 400):
            start = time.perf_counter()
            png = generate_avatar(
                "size::test", "bots", size, library_path=AVATARS_PATH
            )
            elapsed = time.perf_counter() - start

            assert png[:8] == b"\x89PNG\r\n\x1a\n"
            assert len(png) > 0

            if size == 200:
                times_200.append(elapsed)
            elif size == 400:
                times_400.append(elapsed)

        # 400px should take no more than 3x the 200px time
        if times_200 and times_400:
            assert times_400[0] < times_200[0] * 3 + 0.05  # Small buffer for overhead


# ---------------------------------------------------------------------------
# TestCacheBehavior
# ---------------------------------------------------------------------------


class TestCacheBehavior:
    """Tests for library cache clearing and reloading."""

    def test_cache_cleared(self) -> None:
        """After clear_library_cache, discover_libraries still works (reloads)."""
        # First discovery
        libs1 = discover_libraries(AVATARS_PATH)
        assert "bots" in libs1

        # Clear and rediscover
        clear_library_cache()
        libs2 = discover_libraries(AVATARS_PATH)
        assert "bots" in libs2
