"""The glossary is almost entirely prose, and prose is not testable.

What *is* testable is the structure holding it: a see-also link that points at
nothing, an entry missing a field, a one-line summary that is three lines long.
Those are the things that can be wrong rather than merely badly worded, so they
are what these tests pin. The rest is editing, not engineering.
"""

from netdiff import cli
from netdiff.glossary import TERMS

FIELDS = ("name", "short", "long", "see")


def test_every_see_also_points_at_a_term_that_exists():
    """The one thing in this module that can be broken silently.

    A dead link is invisible until someone types the term it names and is told
    it does not exist - by the command whose whole job is explaining things.
    """
    for slug, entry in TERMS.items():
        for target in entry["see"]:
            assert target in TERMS, f"{slug} points at {target!r}, which is not a term"


def test_every_entry_is_well_formed():
    """`short` is printed in a column beside the slug, so it has to fit on a line."""
    for slug, entry in TERMS.items():
        assert set(entry) == set(FIELDS), f"{slug} has the wrong fields"
        assert entry["name"] and entry["long"], f"{slug} is missing text"
        assert slug == slug.lower() and " " not in slug, f"{slug} is not a slug"
        short = entry["short"]
        assert short and "\n" not in short, f"{slug} has no usable summary"
        assert len(short) <= 80, f"{slug} summary is {len(short)} chars, too long"


def test_the_list_names_every_term(capsys):
    assert cli.main(["glossary"]) == 0
    out = capsys.readouterr().out
    for slug in TERMS:
        assert slug in out


def test_one_term_prints_its_whole_entry(capsys):
    assert cli.main(["glossary", "upnp"]) == 0
    out = capsys.readouterr().out
    assert TERMS["upnp"]["name"] in out
    # Wrapped across lines by print_field, so a distinctive phrase rather than
    # the paragraph - checking the whole string would only test textwrap.
    assert "no password and no prompt" in out.replace("\n", " ").replace("  ", " ")
    assert "port-forward" in out, "see-also links are how you keep reading"


def test_a_term_is_found_however_it_was_typed(capsys):
    assert cli.main(["glossary", "UPnP"]) == 0
    assert TERMS["upnp"]["name"] in capsys.readouterr().out


def test_an_unknown_term_says_what_is_known(capsys):
    """Same shape as `audit --explain` on an unknown rule: exit 2, list, stderr."""
    assert cli.main(["glossary", "quantum"]) == 2
    err = capsys.readouterr().err
    assert "quantum" in err and "arp" in err
