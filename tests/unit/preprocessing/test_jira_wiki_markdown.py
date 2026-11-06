"""Tests for the Jira wiki markup to Markdown conversion."""

import pytest

from mcp_atlassian.preprocessing.jira_wiki_markdown import wiki_to_markdown


def md(text, **kwargs):
    return wiki_to_markdown(text, **kwargs).markdown


@pytest.mark.parametrize(
    ("wiki", "expected"),
    [
        ("*fett*", "**fett**"),
        ("_kursiv_", "*kursiv*"),
        ("-gestrichen-", "~~gestrichen~~"),
        ("+unterstrichen+", "<ins>unterstrichen</ins>"),
        ("x^2^ und H~2~O", "x^2^ und H~2~O".replace("x^2^", "x^2^")),
        ("{{code_mit_unterstrich}}", "`code_mit_unterstrich`"),
        ("snake_case_name bleibt", "snake_case_name bleibt"),
        ("2026-03-26 bleibt", "2026-03-26 bleibt"),
        ("Ein- und Ausgabe", "Ein- und Ausgabe"),
        ("a*b*c", "a\\*b\\*c"),
        ("Wert <Kürzel> und <b>", "Wert \\<Kürzel> und \\<b>"),
        ("a -- b --- c", "a – b — c"),
        ("Zeile\\\\zwei", "Zeile<br>zwei"),
        ("h2. Titel *fett*", "## Titel **fett**"),
        ("bq. Zitat", "> Zitat"),
        ("----", "---"),
        ("(/) erledigt (x) offen", "✅ erledigt ❌ offen"),
        ("[Testing] - [Bug] Titel", "[Testing] - [Bug] Titel"),
    ],
)
def test_inline_and_lines(wiki, expected):
    if "^2^" in wiki:
        assert md(wiki) == "x<sup>2</sup> und H<sub>2</sub>O"
    else:
        assert md(wiki) == expected


def test_urls_keep_underscores_and_query():
    url = "https://example.com/a_b_c/page?x=1&y=*2*"
    assert md(f"Siehe {url} hier") == f"Siehe {url} hier"
    assert md(f"[Text|{url}]") == f"[Text]({url})"


def test_link_text_with_pipe():
    wiki = "[Gruppe: A | B|https://example.com/x]"
    assert md(wiki) == "[Gruppe: A | B](https://example.com/x)"


def test_smart_link_keeps_query_string():
    url = "https://ctr.example.com/start?communityUuid=6036-9fb0"
    assert md(f"[{url}|{url}|smart-link]") == f"[{url}]({url})"
    assert md(f"[{url}|smart-card]") == f"[{url}]({url})"


def test_bare_url_link():
    assert (
        md("[https://example.com/a_b]")
        == "[https://example.com/a_b](https://example.com/a_b)"
    )


def test_bold_directly_after_link():
    result = md("URL: [https://x.example/|https://x.example/]*access*)")
    assert result == "URL: [https://x.example/](https://x.example/)**access**)"


def test_images_keep_place_and_file_name():
    conv = wiki_to_markdown(
        'Vorher\n!bild 1.png|width=886,alt="bild 1.png"!\nDann !b.jpg! und !https://x.example/i.png!'
    )
    assert conv.markdown == (
        "Vorher\n![bild 1.png](<bild 1.png>)\nDann ![b.jpg](b.jpg) und ![](https://x.example/i.png)"
    )
    assert conv.images == ["bild 1.png", "b.jpg"]


def test_exclamation_marks_are_no_images():
    assert md("Achtung! Das ist wichtig!") == "Achtung! Das ist wichtig!"
    assert md("(!) Hinweis zu datei.png!") == "⚠️ Hinweis zu datei.png!"


def test_attachment_link():
    conv = wiki_to_markdown("Log: [^server log.txt] und [Bericht|^b.pdf]")
    assert (
        conv.markdown == "Log: [server log.txt](<server log.txt>) und [Bericht](b.pdf)"
    )
    assert conv.attachment_links == ["server log.txt", "b.pdf"]


def test_lists_nested_and_separated():
    wiki = "Text:\n* eins\n** zwei_a\n# nummer\n#* gemischt\nDanach"
    assert md(wiki) == "Text:\n\n- eins\n  - zwei_a\n1. nummer\n   - gemischt\n\nDanach"


def test_list_without_parent_level():
    assert md("## a\n## b") == "1. a\n1. b"


def test_bold_line_is_no_list():
    assert md("*1. Titel (ACCESS)*") == "**1. Titel (ACCESS)**"


def test_code_block_verbatim():
    wiki = "{code:java}\nint a_b = 1; // *x*\n{code}\nNach"
    assert md(wiki) == "```java\nint a_b = 1; // *x*\n```\nNach"


def test_noformat_and_quote_and_panel():
    assert md("{noformat}a *b*{noformat}") == "```\na *b*\n```"
    assert md("{quote}\nZitat *fett*\n{quote}") == "> Zitat **fett**"
    assert md("{panel:title=Hinweis}\nText\n{panel}") == "> **Hinweis**\n>\n> Text"


def test_color_removed_text_kept():
    assert md("{color:#ff0000}rot{color} bleibt") == "rot bleibt"


def test_unknown_macro_reported():
    conv = wiki_to_markdown("Status {status:colour=Green|title=OK} hier")
    assert "{status:colour=Green|title=OK}" in conv.markdown
    assert conv.unconverted == ["status"]


def test_table_with_header_and_links():
    wiki = "||Name||Link||\n|a_b|[x|https://e.example/q?a=1]|\n|c|{{d|e}}|"
    assert md(wiki) == (
        "| Name | Link |\n| --- | --- |\n| a_b | [x](https://e.example/q?a=1) |\n| c | `d\\|e` |"
    )


def test_table_without_header():
    assert md("|a|b|") == "|  |  |\n| --- | --- |\n| a | b |"


def test_mentions():
    conv = wiki_to_markdown(
        "Hallo [~accountid:abc] und [~accountid:def]",
        mention=lambda a: "Name A" if a == "abc" else None,
    )
    assert conv.markdown == "Hallo @Name A und [~accountid:def]"
    assert conv.mentions == ["def"]


def test_line_start_markdown_escaped():
    assert md("Text\n---") == "Text\n\\---"
    assert md("> kein Zitat") == "\\> kein Zitat"


def test_description_with_images_and_smart_links():
    wiki = (
        "Aktuell so:\n\n"
        '!image-1.png|width=886,alt="image-1.png"!\n\n\n\n'
        "Die \u201cHilfe\u201d-Kachel bekommt ein Untermen\u00fc analog zu \u201cAdministration\u201d.\n\n"
        "*1. Role request (ACCESS)*\n\n"
        "Erreichbar \u00fcber URL: [https://va.example/|https://va.example/]*access*)\n\n"
        "## Interne Nutzer auf: [Gruppe: A | B|https://social.example/groups/a-b/pages/s]\n"
        "## externe auf: [https://ctr.example/start?communityUuid=6036|https://ctr.example/start?communityUuid=6036|smart-link]  weiter.\n\n"
        "Chat (URL: [https://va.example/|https://va.example/]*chat*).\n\n"
        '!image-2.png|width=886,alt="image-2.png"!'
    )
    conv = wiki_to_markdown(wiki)
    assert conv.images == ["image-1.png", "image-2.png"]
    assert conv.markdown == (
        "Aktuell so:\n\n"
        "![image-1.png](image-1.png)\n\n\n\n"
        "Die \u201cHilfe\u201d-Kachel bekommt ein Untermen\u00fc analog zu \u201cAdministration\u201d.\n\n"
        "**1. Role request (ACCESS)**\n\n"
        "Erreichbar \u00fcber URL: [https://va.example/](https://va.example/)**access**)\n\n"
        "1. Interne Nutzer auf: [Gruppe: A | B](https://social.example/groups/a-b/pages/s)\n"
        "1. externe auf: [https://ctr.example/start?communityUuid=6036](https://ctr.example/start?communityUuid=6036)  weiter.\n\n"
        "Chat (URL: [https://va.example/](https://va.example/)**chat**).\n\n"
        "![image-2.png](image-2.png)"
    )
