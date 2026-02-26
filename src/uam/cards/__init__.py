"""UAM Card Generation Package -- card images and vCard files."""

from uam.cards.image import render_card
from uam.cards.avatars import fetch_avatar
from uam.cards.vcard import generate_reservation_vcard, generate_identity_vcard, fold_line

__all__ = [
    "render_card",
    "fetch_avatar",
    "generate_reservation_vcard",
    "generate_identity_vcard",
    "fold_line",
]
