"""Comprehensive tests for the avatar engine.

Covers manifest validation, library loading, library discovery,
determinism, SVG composition, and error handling. All tests run
offline using temporary test fixtures -- no network calls.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from uam.cards.avatar_engine import (
    AvatarLibrary,
    _compose_svg,
    _select_components,
    clear_library_cache,
    discover_libraries,
    generate_avatar,
    load_library,
    validate_manifest,
)

# ---------------------------------------------------------------------------
# Test fixtures and helpers
# ---------------------------------------------------------------------------

_MINIMAL_SVG = (
    '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200">'
    '<rect width="200" height="200" fill="currentColor"/>'
    "</svg>"
)

_SIMPLE_MANIFEST: dict = {
    "name": "test-lib",
    "version": "1.0.0",
    "width": 200,
    "height": 200,
    "layers": [
        {
            "name": "background",
            "required": True,
            "components": ["bg-01.svg", "bg-02.svg", "bg-03.svg"],
        },
        {
            "name": "body",
            "required": True,
            "components": ["body-01.svg", "body-02.svg", "body-03.svg"],
        },
        {
            "name": "eyes",
            "required": True,
            "components": ["eyes-01.svg", "eyes-02.svg", "eyes-03.svg"],
        },
    ],
    "palettes": [
        {
            "name": "warm",
            "background": "#1a1a2e",
            "accent": "#e2b714",
            "colors": ["#ff6600"],
        },
        {
            "name": "cool",
            "background": "#0d2137",
            "accent": "#00d4ff",
            "colors": ["#0066ff"],
        },
    ],
}


def _create_test_library(
    tmp_path: Path,
    name: str = "test-lib",
    manifest: dict | None = None,
    *,
    skip_svg_files: list[str] | None = None,
    corrupt_svg: str | None = None,
) -> Path:
    """Create a test library directory with manifest and SVG files.

    Args:
        tmp_path: Temporary directory root.
        name: Subdirectory name for the library.
        manifest: Manifest dict (defaults to _SIMPLE_MANIFEST).
        skip_svg_files: SVG filenames to NOT create (for missing-file tests).
        corrupt_svg: If set, write this content instead of valid SVG for all files.

    Returns:
        Path to the created library directory.
    """
    if manifest is None:
        manifest = _SIMPLE_MANIFEST.copy()

    lib_dir = tmp_path / name
    lib_dir.mkdir(exist_ok=True)

    # Write manifest
    (lib_dir / "manifest.json").write_text(json.dumps(manifest))

    # Create SVG component files
    skip = set(skip_svg_files or [])
    for layer in manifest.get("layers", []):
        for comp in layer.get("components", []):
            if comp in skip:
                continue
            svg_content = corrupt_svg if corrupt_svg else _MINIMAL_SVG
            (lib_dir / comp).write_text(svg_content)

    return lib_dir


# ---------------------------------------------------------------------------
# TestManifestValidation
# ---------------------------------------------------------------------------


class TestManifestValidation:
    """Tests for validate_manifest() schema checking."""

    def test_valid_manifest_passes(self) -> None:
        """Complete valid manifest does not raise."""
        validate_manifest(_SIMPLE_MANIFEST)

    def test_missing_name_raises(self) -> None:
        """Missing 'name' key raises ValueError with 'name' in message."""
        data = {k: v for k, v in _SIMPLE_MANIFEST.items() if k != "name"}
        with pytest.raises(ValueError, match="name"):
            validate_manifest(data)

    def test_missing_layers_raises(self) -> None:
        """Missing 'layers' key raises ValueError."""
        data = {k: v for k, v in _SIMPLE_MANIFEST.items() if k != "layers"}
        with pytest.raises(ValueError, match="layers"):
            validate_manifest(data)

    def test_empty_layers_raises(self) -> None:
        """Empty layers list raises ValueError."""
        data = {**_SIMPLE_MANIFEST, "layers": []}
        with pytest.raises(ValueError, match="layers"):
            validate_manifest(data)

    def test_missing_palettes_raises(self) -> None:
        """Missing 'palettes' key raises ValueError."""
        data = {k: v for k, v in _SIMPLE_MANIFEST.items() if k != "palettes"}
        with pytest.raises(ValueError, match="palettes"):
            validate_manifest(data)

    def test_empty_palettes_raises(self) -> None:
        """Empty palettes list raises ValueError."""
        data = {**_SIMPLE_MANIFEST, "palettes": []}
        with pytest.raises(ValueError, match="palettes"):
            validate_manifest(data)

    def test_invalid_layer_missing_components(self) -> None:
        """Layer without 'components' key raises ValueError."""
        bad_layers = [{"name": "bg", "required": True}]
        data = {**_SIMPLE_MANIFEST, "layers": bad_layers}
        with pytest.raises(ValueError, match="components"):
            validate_manifest(data)

    def test_empty_components_raises(self) -> None:
        """Layer with empty components list raises ValueError."""
        bad_layers = [{"name": "bg", "required": True, "components": []}]
        data = {**_SIMPLE_MANIFEST, "layers": bad_layers}
        with pytest.raises(ValueError, match="components"):
            validate_manifest(data)


# ---------------------------------------------------------------------------
# TestLoadLibrary
# ---------------------------------------------------------------------------


class TestLoadLibrary:
    """Tests for load_library() filesystem loading."""

    def test_loads_valid_library(self, tmp_path: Path) -> None:
        """Valid library directory loads into AvatarLibrary with correct fields."""
        lib_dir = _create_test_library(tmp_path)
        lib = load_library(lib_dir)
        assert isinstance(lib, AvatarLibrary)
        assert lib.name == "test-lib"
        assert lib.version == "1.0.0"
        assert lib.width == 200
        assert lib.height == 200
        assert len(lib.layers) == 3
        assert len(lib.palettes) == 2
        assert lib.base_path == lib_dir

    def test_missing_manifest_raises(self, tmp_path: Path) -> None:
        """Directory without manifest.json raises FileNotFoundError."""
        empty_dir = tmp_path / "empty"
        empty_dir.mkdir()
        with pytest.raises(FileNotFoundError):
            load_library(empty_dir)

    def test_missing_svg_file_raises(self, tmp_path: Path) -> None:
        """Manifest referencing nonexistent SVG raises ValueError at load time."""
        lib_dir = _create_test_library(tmp_path, skip_svg_files=["bg-01.svg"])
        with pytest.raises(ValueError, match="missing"):
            load_library(lib_dir)

    def test_invalid_json_raises(self, tmp_path: Path) -> None:
        """Invalid JSON in manifest.json raises error at load time."""
        lib_dir = tmp_path / "bad-json"
        lib_dir.mkdir()
        (lib_dir / "manifest.json").write_text("{not valid json!!!")
        with pytest.raises(json.JSONDecodeError):
            load_library(lib_dir)


# ---------------------------------------------------------------------------
# TestDiscoverLibraries
# ---------------------------------------------------------------------------


class TestDiscoverLibraries:
    """Tests for discover_libraries() directory scanning."""

    def test_discovers_multiple_libraries(self, tmp_path: Path) -> None:
        """Two valid library directories are both discovered."""
        manifest_a = {**_SIMPLE_MANIFEST, "name": "lib-a"}
        manifest_b = {**_SIMPLE_MANIFEST, "name": "lib-b"}
        _create_test_library(tmp_path, name="lib-a", manifest=manifest_a)
        _create_test_library(tmp_path, name="lib-b", manifest=manifest_b)

        libs = discover_libraries(tmp_path)
        assert "lib-a" in libs
        assert "lib-b" in libs
        assert len(libs) == 2

    def test_skips_invalid_libraries(self, tmp_path: Path) -> None:
        """One valid + one invalid directory returns only the valid one."""
        _create_test_library(tmp_path, name="valid")

        # Create an invalid library (bad manifest)
        bad_dir = tmp_path / "bad"
        bad_dir.mkdir()
        (bad_dir / "manifest.json").write_text("{}")

        libs = discover_libraries(tmp_path)
        assert "test-lib" in libs
        assert len(libs) == 1

    def test_empty_directory_returns_empty(self, tmp_path: Path) -> None:
        """Empty directory returns empty dict."""
        empty = tmp_path / "empty-search"
        empty.mkdir()
        libs = discover_libraries(empty)
        assert libs == {}


# ---------------------------------------------------------------------------
# TestDeterminism
# ---------------------------------------------------------------------------


class TestDeterminism:
    """Tests for deterministic output from the same inputs."""

    @pytest.fixture(autouse=True)
    def _setup_library(self, tmp_path: Path) -> None:
        """Create a test library with enough variants for meaningful tests."""
        clear_library_cache()
        # Use a richer library with 5 components per layer for better distribution
        manifest = {
            "name": "det-test",
            "version": "1.0.0",
            "width": 200,
            "height": 200,
            "layers": [
                {
                    "name": "background",
                    "required": True,
                    "components": [f"bg-{i:02d}.svg" for i in range(5)],
                },
                {
                    "name": "body",
                    "required": True,
                    "components": [f"body-{i:02d}.svg" for i in range(5)],
                },
                {
                    "name": "eyes",
                    "required": True,
                    "components": [f"eyes-{i:02d}.svg" for i in range(5)],
                },
            ],
            "palettes": [
                {
                    "name": f"p{i}",
                    "background": f"#{i:02x}{i:02x}{i:02x}",
                    "accent": f"#{(i*40):02x}aa{(i*20):02x}",
                    "colors": [],
                }
                for i in range(4)
            ],
        }
        self._lib_dir = _create_test_library(tmp_path, name="det-test", manifest=manifest)
        self._lib_path = tmp_path

    def test_same_address_same_output(self) -> None:
        """generate_avatar called 100 times produces identical bytes."""
        clear_library_cache()
        first = generate_avatar(
            "alice::relay.example", "det-test", library_path=self._lib_path
        )
        for _ in range(99):
            result = generate_avatar(
                "alice::relay.example", "det-test", library_path=self._lib_path
            )
            assert result == first

    def test_different_addresses_different_output(self) -> None:
        """10 different addresses produce multiple distinct PNG outputs.

        Note: With test SVGs that are identical shapes (just colored rectangles),
        visual variation comes primarily from palette selection. With 4 palettes,
        we expect at least 3 distinct outputs from 10 random addresses.  Real
        asset libraries with visually distinct component SVGs will produce far
        more variation.
        """
        clear_library_cache()
        outputs = set()
        for i in range(10):
            png = generate_avatar(
                f"user{i}::relay.example", "det-test", library_path=self._lib_path
            )
            outputs.add(png)
        # With 4 palettes and identical SVG shapes, expect at least 3 distinct
        # PNG outputs.  The component selection IS different per address (verified
        # by test_component_selection_uniform), but identical SVG content means
        # visual output only varies by palette color.
        assert len(outputs) >= 3

    def test_component_selection_uniform(self) -> None:
        """1000 addresses use each component in each layer at least once."""
        clear_library_cache()
        libs = discover_libraries(self._lib_path)
        lib = libs["det-test"]

        # Track which components get selected per layer
        layer_selections: dict[str, set[str]] = {
            layer["name"]: set() for layer in lib.layers
        }

        for i in range(1000):
            address = f"uniformity-test-{i}::relay.example"
            components, _ = _select_components(address, lib)
            for layer_name, comp_path in components:
                if comp_path is not None:
                    layer_selections[layer_name].add(comp_path.name)

        # Each layer should have all 5 components selected at least once
        for layer_name, selected in layer_selections.items():
            assert len(selected) == 5, (
                f"Layer '{layer_name}' only selected {len(selected)}/5 components: "
                f"{selected}"
            )


# ---------------------------------------------------------------------------
# TestSVGComposition
# ---------------------------------------------------------------------------


class TestSVGComposition:
    """Tests for SVG layer composition and PNG rasterization."""

    @pytest.fixture(autouse=True)
    def _setup_library(self, tmp_path: Path) -> None:
        clear_library_cache()
        self._lib_dir = _create_test_library(tmp_path)
        self._lib_path = tmp_path

    def test_output_is_valid_png(self) -> None:
        """Result starts with PNG magic bytes."""
        clear_library_cache()
        png = generate_avatar(
            "test::relay.example", "test-lib", library_path=self._lib_path
        )
        assert png[:8] == b"\x89PNG\r\n\x1a\n"

    def test_custom_size(self) -> None:
        """generate_avatar with different sizes produces valid PNGs."""
        clear_library_cache()
        for size in (100, 400):
            png = generate_avatar(
                "test::relay.example",
                "test-lib",
                size=size,
                library_path=self._lib_path,
            )
            assert png[:8] == b"\x89PNG\r\n\x1a\n"
            assert len(png) > 0

    def test_palette_applied(self) -> None:
        """currentColor is replaced with palette accent color in composed SVG."""
        clear_library_cache()
        libs = discover_libraries(self._lib_path)
        lib = libs["test-lib"]
        components, palette = _select_components("test::relay.example", lib)
        svg = _compose_svg(lib, components, palette)

        # currentColor should NOT appear in the composed SVG
        assert "currentColor" not in svg
        # The palette accent color SHOULD appear
        assert palette["accent"] in svg

    def test_named_color_tokens_replaced(self, tmp_path: Path) -> None:
        """Palette colors dict replaces TOKEN_ strings in SVGs."""
        clear_library_cache()
        token_svg = (
            '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 200 200">'
            '<rect fill="TOKEN_BASE" stroke="TOKEN_DARK"/>'
            '<circle fill="TOKEN_JOINT" stroke="TOKEN_OUTLINE"/>'
            "</svg>"
        )
        manifest = {
            "name": "token-test",
            "version": "1.0.0",
            "width": 200,
            "height": 200,
            "layers": [
                {"name": "body", "required": True, "components": ["body.svg"]},
            ],
            "palettes": [
                {
                    "name": "crimson",
                    "background": "#1a1a2e",
                    "accent": "#ef4444",
                    "colors": {
                        "base": "#ef4444",
                        "dark": "#b91c1c",
                        "joint": "#991b1b",
                        "outline": "#1e293b",
                    },
                },
            ],
        }
        lib_dir = tmp_path / "token-test"
        lib_dir.mkdir()
        (lib_dir / "manifest.json").write_text(json.dumps(manifest))
        (lib_dir / "body.svg").write_text(token_svg)

        png = generate_avatar("test::addr", "token-test", library_path=tmp_path)
        assert png[:8] == b"\x89PNG\r\n\x1a\n"

        # Also verify the SVG composition replaces tokens
        libs = discover_libraries(tmp_path)
        lib = libs["token-test"]
        components, palette = _select_components("test::addr", lib)
        svg = _compose_svg(lib, components, palette)
        assert "TOKEN_BASE" not in svg
        assert "TOKEN_DARK" not in svg
        assert "TOKEN_JOINT" not in svg
        assert "TOKEN_OUTLINE" not in svg
        assert "#ef4444" in svg
        assert "#b91c1c" in svg
        assert "#991b1b" in svg
        assert "#1e293b" in svg


# ---------------------------------------------------------------------------
# TestLinkedLayers
# ---------------------------------------------------------------------------


class TestLinkedLayers:
    """Tests for linked_to layer selection."""

    def test_linked_layer_matches_source(self, tmp_path: Path) -> None:
        """A layer with linked_to always selects the same index as its source."""
        clear_library_cache()
        manifest = {
            "name": "linked-test",
            "version": "1.0.0",
            "width": 200,
            "height": 200,
            "layers": [
                {
                    "name": "base",
                    "required": True,
                    "components": ["a.svg", "b.svg", "c.svg", "d.svg"],
                },
                {
                    "name": "middle",
                    "required": True,
                    "components": ["m.svg"],
                },
                {
                    "name": "highlight",
                    "required": True,
                    "linked_to": "base",
                    "components": ["ha.svg", "hb.svg", "hc.svg", "hd.svg"],
                },
            ],
            "palettes": [
                {"name": "default", "background": "#fff", "accent": "#000", "colors": []},
            ],
        }
        lib_dir = tmp_path / "linked-test"
        lib_dir.mkdir()
        (lib_dir / "manifest.json").write_text(json.dumps(manifest))
        for name in ["a", "b", "c", "d", "m", "ha", "hb", "hc", "hd"]:
            (lib_dir / f"{name}.svg").write_text(_MINIMAL_SVG)

        libs = discover_libraries(tmp_path)
        lib = libs["linked-test"]

        # Test 100 different addresses — highlight index must always match base index
        for i in range(100):
            components, _ = _select_components(f"test-{i}::relay", lib)
            base_file = components[0][1].stem  # a, b, c, or d
            highlight_file = components[2][1].stem  # ha, hb, hc, or hd
            base_idx = ["a", "b", "c", "d"].index(base_file)
            highlight_idx = ["ha", "hb", "hc", "hd"].index(highlight_file)
            assert base_idx == highlight_idx, (
                f"Address test-{i}: base={base_file} (idx {base_idx}) "
                f"but highlight={highlight_file} (idx {highlight_idx})"
            )


# ---------------------------------------------------------------------------
# TestErrorHandling
# ---------------------------------------------------------------------------


class TestErrorHandling:
    """Tests for error conditions."""

    def test_unknown_style_raises(self, tmp_path: Path) -> None:
        """generate_avatar with nonexistent style raises ValueError."""
        clear_library_cache()
        _create_test_library(tmp_path)
        with pytest.raises(ValueError, match="Unknown avatar style"):
            generate_avatar(
                "test::relay.example",
                "nonexistent-style",
                library_path=tmp_path,
            )

    def test_corrupt_svg_raises(self, tmp_path: Path) -> None:
        """Library with invalid XML in SVG file raises an error during generation."""
        clear_library_cache()
        _create_test_library(
            tmp_path,
            name="corrupt",
            manifest={**_SIMPLE_MANIFEST, "name": "corrupt"},
            corrupt_svg="<not-valid-xml>>>>>",
        )
        with pytest.raises(Exception):
            generate_avatar(
                "test::relay.example", "corrupt", library_path=tmp_path
            )
