"""Deterministic avatar engine using SVG composition and CairoSVG rasterization.

Generates PNG avatar images from bundled SVG asset libraries without any
HTTP calls. Each address produces a deterministic avatar via SHA-256
seeding for component selection.

Asset libraries are directories containing a manifest.json and SVG files.
The manifest defines layers (z-order), component variants per layer, and
color palettes. The engine selects components deterministically from the
address hash and composites them into a single SVG, which is then
rasterized to PNG via CairoSVG.
"""

from __future__ import annotations

import hashlib
import json
import logging
import xml.etree.ElementTree as ET
from dataclasses import dataclass
from pathlib import Path

import cairosvg

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# SVG namespace registration (prevents ns0: prefix pollution)
# ---------------------------------------------------------------------------

_SVG_NS = "http://www.w3.org/2000/svg"
ET.register_namespace("", _SVG_NS)

# ---------------------------------------------------------------------------
# Manifest schema validation
# ---------------------------------------------------------------------------


def validate_manifest(data: dict) -> None:
    """Validate an asset library manifest against the required schema.

    Raises ValueError with a clear message if any required field is missing
    or has the wrong type.  Validation happens at load time so errors surface
    early -- never at render time.
    """
    # Top-level required string fields
    for field in ("name", "version"):
        if field not in data:
            raise ValueError(f"Manifest missing required field: '{field}'")
        if not isinstance(data[field], str) or not data[field].strip():
            raise ValueError(f"Manifest field '{field}' must be a non-empty string")

    # Top-level required positive int fields
    for field in ("width", "height"):
        if field not in data:
            raise ValueError(f"Manifest missing required field: '{field}'")
        if not isinstance(data[field], int) or data[field] <= 0:
            raise ValueError(f"Manifest field '{field}' must be a positive integer")

    # Layers validation
    if "layers" not in data:
        raise ValueError("Manifest missing required field: 'layers'")
    if not isinstance(data["layers"], list) or len(data["layers"]) == 0:
        raise ValueError("Manifest field 'layers' must be a non-empty list")

    for i, layer in enumerate(data["layers"]):
        if not isinstance(layer, dict):
            raise ValueError(f"Manifest layer[{i}] must be a dict")
        if "name" not in layer or not isinstance(layer["name"], str):
            raise ValueError(f"Manifest layer[{i}] missing required field 'name' (str)")
        if "required" not in layer or not isinstance(layer["required"], bool):
            raise ValueError(f"Manifest layer[{i}] missing required field 'required' (bool)")
        if "components" not in layer:
            raise ValueError(f"Manifest layer[{i}] missing required field 'components'")
        if not isinstance(layer["components"], list) or len(layer["components"]) == 0:
            raise ValueError(
                f"Manifest layer[{i}] field 'components' must be a non-empty list"
            )
        for j, comp in enumerate(layer["components"]):
            if not isinstance(comp, str):
                raise ValueError(
                    f"Manifest layer[{i}].components[{j}] must be a string"
                )

    # Palettes validation
    if "palettes" not in data:
        raise ValueError("Manifest missing required field: 'palettes'")
    if not isinstance(data["palettes"], list) or len(data["palettes"]) == 0:
        raise ValueError("Manifest field 'palettes' must be a non-empty list")

    for i, palette in enumerate(data["palettes"]):
        if not isinstance(palette, dict):
            raise ValueError(f"Manifest palette[{i}] must be a dict")
        for field in ("name", "background", "accent"):
            if field not in palette or not isinstance(palette[field], str):
                raise ValueError(
                    f"Manifest palette[{i}] missing required field '{field}' (str)"
                )


# ---------------------------------------------------------------------------
# AvatarLibrary dataclass
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class AvatarLibrary:
    """A loaded asset library with validated manifest and base path."""

    name: str
    version: str
    width: int
    height: int
    layers: list[dict]
    palettes: list[dict]
    base_path: Path
    shape: str = "square"  # "square" or "circle"


# ---------------------------------------------------------------------------
# Library loading and discovery
# ---------------------------------------------------------------------------


def load_library(path: Path) -> AvatarLibrary:
    """Load an asset library from a directory containing manifest.json.

    Validates the manifest schema and verifies that all referenced SVG
    component files actually exist on disk.  Raises at load time, never
    at render time.

    Args:
        path: Directory containing manifest.json and SVG component files.

    Returns:
        A validated AvatarLibrary instance.

    Raises:
        FileNotFoundError: If path or manifest.json does not exist.
        ValueError: If manifest is invalid or references missing SVG files.
        json.JSONDecodeError: If manifest.json contains invalid JSON.
    """
    manifest_path = path / "manifest.json"
    if not manifest_path.exists():
        raise FileNotFoundError(f"No manifest.json found in {path}")

    with open(manifest_path, "r") as f:
        data = json.load(f)

    validate_manifest(data)

    # Verify all referenced SVG component files exist on disk
    for layer in data["layers"]:
        for component in layer["components"]:
            svg_path = path / component
            if not svg_path.exists():
                raise ValueError(
                    f"Component SVG file missing: {svg_path} "
                    f"(referenced in layer '{layer['name']}')"
                )

    return AvatarLibrary(
        name=data["name"],
        version=data["version"],
        width=data["width"],
        height=data["height"],
        layers=data["layers"],
        palettes=data["palettes"],
        base_path=path,
        shape=data.get("shape", "square"),
    )


def discover_libraries(search_path: Path) -> dict[str, AvatarLibrary]:
    """Scan a directory for subdirectories containing valid asset libraries.

    Each subdirectory with a manifest.json is attempted as a library.
    Invalid libraries are skipped with a warning log.

    Args:
        search_path: Root directory to scan for library subdirectories.

    Returns:
        Dict mapping library name to AvatarLibrary instance.
    """
    libraries: dict[str, AvatarLibrary] = {}

    if not search_path.is_dir():
        return libraries

    for child in sorted(search_path.iterdir()):
        if not child.is_dir():
            continue
        manifest = child / "manifest.json"
        if not manifest.exists():
            continue
        try:
            lib = load_library(child)
            libraries[lib.name] = lib
        except Exception as exc:
            logger.warning("Skipping invalid library at %s: %s", child, exc)

    return libraries


# ---------------------------------------------------------------------------
# Library cache
# ---------------------------------------------------------------------------

_library_cache: dict[Path, dict[str, AvatarLibrary]] = {}


def clear_library_cache() -> None:
    """Clear the library discovery cache (useful for tests)."""
    _library_cache.clear()


def _get_libraries(library_path: Path) -> dict[str, AvatarLibrary]:
    """Get libraries from cache or discover them."""
    if library_path not in _library_cache:
        _library_cache[library_path] = discover_libraries(library_path)
    return _library_cache[library_path]


# ---------------------------------------------------------------------------
# Deterministic component selection
# ---------------------------------------------------------------------------


def _select_components(
    address: str, library: AvatarLibrary
) -> tuple[list[tuple[str, Path | None]], dict]:
    """Select components and palette deterministically from the address hash.

    Uses SHA-256 of the address to produce a 32-byte seed.  Each layer
    consumes 4 bytes (cycling through the seed) to pick a component index.
    The palette is selected using the first 4 bytes.

    Returns:
        Tuple of (component list, selected palette dict).
        Each component is (layer_name, svg_path) or (layer_name, None) for
        optional layers that are skipped.
    """
    seed = hashlib.sha256(address.encode()).digest()

    # Select palette from first 4 bytes
    palette_index = int.from_bytes(seed[0:4], "big") % len(library.palettes)
    palette = library.palettes[palette_index]

    components: list[tuple[str, Path | None]] = []
    layer_indices: dict[str, int] = {}  # name -> selected component index
    for i, layer in enumerate(library.layers):
        linked_to = layer.get("linked_to")
        if linked_to and linked_to in layer_indices:
            # Reuse the same component index as the linked layer
            comp_index = layer_indices[linked_to] % len(layer["components"])
        else:
            offset = (i * 4) % 32
            # Handle wrap-around: if offset+4 exceeds 32, wrap the seed bytes
            if offset + 4 <= 32:
                seed_bytes = seed[offset : offset + 4]
            else:
                seed_bytes = (seed + seed)[offset : offset + 4]
            seed_int = int.from_bytes(seed_bytes, "big")
            comp_index = seed_int % len(layer["components"])
        layer_indices[layer["name"]] = comp_index
        comp_filename = layer["components"][comp_index]
        comp_path = library.base_path / comp_filename
        components.append((layer["name"], comp_path))

    return components, palette


# ---------------------------------------------------------------------------
# SVG composition
# ---------------------------------------------------------------------------


def _compose_svg(
    library: AvatarLibrary,
    components: list[tuple[str, Path | None]],
    palette: dict,
) -> str:
    """Compose SVG layers into a single SVG document.

    Creates a root SVG with a background rectangle, then overlays each
    component SVG's children in z-order (list order = bottom to top).
    Applies palette accent color by replacing 'currentColor' in SVG content.

    Returns:
        Composed SVG as a UTF-8 string.
    """
    w = library.width
    h = library.height
    is_circle = library.shape == "circle"

    # Create root SVG element
    # Note: do NOT set xmlns as an explicit attribute -- ET.register_namespace
    # already handles the default namespace prefix, and ET.tostring will emit
    # the xmlns declaration automatically.  Setting it explicitly causes a
    # "duplicate attribute" error in CairoSVG's parser.
    root = ET.Element(
        f"{{{_SVG_NS}}}svg",
        {
            "viewBox": f"0 0 {w} {h}",
            "width": str(w),
            "height": str(h),
        },
    )

    if is_circle:
        # Add circular clip-path definition
        defs = ET.SubElement(root, f"{{{_SVG_NS}}}defs")
        clip = ET.SubElement(defs, f"{{{_SVG_NS}}}clipPath", {"id": "avatar-circle"})
        ET.SubElement(
            clip,
            f"{{{_SVG_NS}}}circle",
            {"cx": str(w // 2), "cy": str(h // 2), "r": str(min(w, h) // 2)},
        )
        # Wrap all content in clipped group
        content_group = ET.SubElement(
            root, f"{{{_SVG_NS}}}g", {"clip-path": "url(#avatar-circle)"}
        )
        # Circular background
        ET.SubElement(
            content_group,
            f"{{{_SVG_NS}}}circle",
            {
                "cx": str(w // 2),
                "cy": str(h // 2),
                "r": str(min(w, h) // 2),
                "fill": palette["background"],
            },
        )
    else:
        content_group = root
        # Rectangular background
        ET.SubElement(
            content_group,
            f"{{{_SVG_NS}}}rect",
            {
                "width": str(w),
                "height": str(h),
                "fill": palette["background"],
            },
        )

    # Layer each component in z-order
    for _layer_name, comp_path in components:
        if comp_path is None:
            continue

        # Read SVG file and apply palette color replacement
        svg_content = comp_path.read_text(encoding="utf-8")
        svg_content = svg_content.replace("currentColor", palette["accent"])

        # Replace named color tokens from palette colors dict (if present)
        colors = palette.get("colors")
        if isinstance(colors, dict):
            for token_name, color_value in colors.items():
                svg_content = svg_content.replace(
                    f"TOKEN_{token_name.upper()}", color_value
                )

        # Parse the component SVG
        try:
            comp_root = ET.fromstring(svg_content)
        except ET.ParseError:
            raise ValueError(f"Invalid SVG file: {comp_path}")

        # Extract child elements from the component SVG root and append
        for child in comp_root:
            content_group.append(child)

    return ET.tostring(root, encoding="unicode")


# ---------------------------------------------------------------------------
# PNG rasterization
# ---------------------------------------------------------------------------


def _rasterize(svg_string: str, size: int) -> bytes:
    """Rasterize an SVG string to PNG bytes at the given size.

    Uses CairoSVG for high-quality rendering.
    """
    return cairosvg.svg2png(
        bytestring=svg_string.encode("utf-8"),
        output_width=size,
        output_height=size,
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

_DEFAULT_LIBRARY_PATH = Path(__file__).parent / "avatars"


def generate_avatar(
    address: str,
    style: str,
    size: int = 200,
    *,
    library_path: Path | None = None,
) -> bytes:
    """Generate a deterministic PNG avatar for the given address and style.

    Uses SHA-256 hashing for deterministic component selection, composites
    SVG layers from the named asset library, and rasterizes to PNG.  No
    HTTP calls are made -- everything is local.

    Args:
        address: Agent address used as the deterministic seed.
        style: Asset library name (e.g., "bots", "crustaceans").
        size: Output PNG size in pixels (default: 200).
        library_path: Root directory containing asset library subdirectories.
            Defaults to the bundled ``avatars/`` directory.

    Returns:
        Raw PNG bytes.

    Raises:
        ValueError: If the requested style is not found among discovered
            libraries.
    """
    if library_path is None:
        library_path = _DEFAULT_LIBRARY_PATH

    libraries = _get_libraries(library_path)

    if style not in libraries:
        available = ", ".join(sorted(libraries.keys())) if libraries else "(none)"
        raise ValueError(
            f"Unknown avatar style '{style}'. Available styles: {available}"
        )

    library = libraries[style]
    components, palette = _select_components(address, library)
    svg_string = _compose_svg(library, components, palette)
    return _rasterize(svg_string, size)
