"""Tests for dnser.output: markup, colors, tables, and the --no-color flag."""

from __future__ import annotations

import io

import pytest

from dnser import cli, output
from dnser.output import Console, Table, escape, render_markup, set_color

RESET = "\x1b[0m"


@pytest.fixture(autouse=True)
def clean_output_state(monkeypatch):
    """Auto color detection, no NO_COLOR, and a fixed terminal width."""
    monkeypatch.delenv("NO_COLOR", raising=False)
    monkeypatch.setenv("TERM", "xterm-256color")
    monkeypatch.setenv("COLUMNS", "200")
    set_color(None)
    yield
    set_color(None)


class FakeTTY(io.StringIO):
    def isatty(self) -> bool:
        return True


# ----------------------------------------------------------------------
# Markup
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    "text",
    ["plain", "[red]x[/red]", "[/]", "trailing\\", "a\\[b", "C:\\dir\\[x]", "[0] [y/N]"],
)
def test_escape_round_trips_untrusted_text(text):
    assert render_markup(escape(text)) == text
    assert render_markup(escape(text), color=True) == text  # no tags, no color codes


def test_escaped_trailing_backslash_does_not_eat_next_tag():
    name = escape("dir\\")
    assert render_markup(f"[dim]{name}[/dim] ok") == "dir\\ ok"


def test_tags_are_dropped_without_color():
    assert render_markup("[bold yellow]dry run[/bold yellow] — [green]OK[/]") == "dry run — OK"


def test_unknown_words_in_brackets_are_text():
    assert render_markup("[default] [0] [31m [ x ] []") == "[default] [0] [31m [ x ] []"


def test_control_characters_are_stripped():
    rendered = render_markup(escape("evil\x1b[31mred\x07\x9b\tok\n"), color=True)
    assert rendered == "evil[31mred\tok\n"


def test_color_codes():
    assert render_markup("[green]ok[/green]", color=True) == f"\x1b[32mok{RESET}"
    assert render_markup("[bold cyan]h[/]", color=True) == f"\x1b[1;36mh{RESET}"


def test_nested_tags_restore_the_outer_style():
    rendered = render_markup("[bold]a [red]b[/red] c[/bold]", color=True)
    assert rendered == f"\x1b[1ma \x1b[31mb{RESET}\x1b[1m c{RESET}"


def test_unclosed_tag_is_reset_at_the_end():
    assert render_markup("[yellow]warn", color=True) == f"\x1b[33mwarn{RESET}"


def test_base_style_wraps_everything():
    rendered = render_markup("bad [dim]x[/dim]", color=True, style="bold red")
    assert rendered == f"\x1b[1;31mbad \x1b[2mx{RESET}\x1b[1;31m{RESET}"


# ----------------------------------------------------------------------
# Color detection
# ----------------------------------------------------------------------


def test_color_on_for_a_terminal():
    assert output._color_enabled(FakeTTY())


def test_color_off_when_piped():
    assert not output._color_enabled(io.StringIO())


def test_no_color_env_disables(monkeypatch):
    monkeypatch.setenv("NO_COLOR", "1")
    assert not output._color_enabled(FakeTTY())


def test_dumb_terminal_disables(monkeypatch):
    monkeypatch.setenv("TERM", "dumb")
    assert not output._color_enabled(FakeTTY())


def test_set_color_overrides_detection():
    set_color(False)
    assert not output._color_enabled(FakeTTY())
    set_color(True)
    assert output._color_enabled(io.StringIO())


# ----------------------------------------------------------------------
# Console
# ----------------------------------------------------------------------


def test_console_writes_to_the_right_stream(capsys):
    Console().print("[green]OK[/green] applied")
    Console().print()
    Console(stderr=True, style="bold red").print(escape("bad [x]"))

    captured = capsys.readouterr()
    assert captured.out == "OK applied\n\n"
    assert captured.err == "bad [x]\n"


def test_console_colors_a_terminal(monkeypatch):
    stream = FakeTTY()
    monkeypatch.setattr("sys.stdout", stream)
    Console().print("[green]OK[/green]")
    assert stream.getvalue() == f"\x1b[32mOK{RESET}\n"


def test_console_survives_a_non_utf8_stream(monkeypatch):
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="ascii")
    monkeypatch.setattr("sys.stdout", stream)
    Console().print("✓ ok")
    stream.flush()
    assert raw.getvalue() == b"? ok\n"


# ----------------------------------------------------------------------
# Tables
# ----------------------------------------------------------------------


def test_table_layout():
    table = Table(title="Protocols", header_style="bold cyan")
    table.add_column("Protocol")
    table.add_column("State")
    table.add_row("LLMNR", "[green]no[/green]")
    table.add_row("DNSOverTLS", "[yellow]opportunistic[/yellow]")

    assert table.render().splitlines() == [
        "          Protocols",
        "┏━━━━━━━━━━━━┳━━━━━━━━━━━━━━━┓",
        "┃ Protocol   ┃ State         ┃",
        "┡━━━━━━━━━━━━╇━━━━━━━━━━━━━━━┩",
        "│ LLMNR      │ no            │",
        "│ DNSOverTLS │ opportunistic │",
        "└────────────┴───────────────┘",
    ]


def test_table_right_justify_sections_and_lines():
    table = Table()
    table.add_column("#", justify="right")
    table.add_column("Label")
    table.add_row("0", "quad9")
    table.add_section()
    table.add_row("10", "mullvad")

    assert table.render().splitlines() == [
        "┏━━━━┳━━━━━━━━━┓",
        "┃  # ┃ Label   ┃",
        "┡━━━━╇━━━━━━━━━┩",
        "│  0 │ quad9   │",
        "├────┼─────────┤",
        "│ 10 │ mullvad │",
        "└────┴─────────┘",
    ]

    table.show_lines = True
    table.add_row("11", "adguard")
    assert table.render().splitlines()[-3:] == [
        "├────┼─────────┤",
        "│ 11 │ adguard │",
        "└────┴─────────┘",
    ]


def test_table_colors_padding_outside_the_codes():
    table = Table(header_style="bold")
    table.add_column("A")
    table.add_column("B", style="bold")
    table.add_row("[red]x[/red]", "y")

    lines = table.render(color=True).splitlines()
    assert lines[1] == f"┃ \x1b[1mA{RESET} ┃ \x1b[1mB{RESET} ┃"
    assert lines[3] == f"│ \x1b[31mx{RESET} │ \x1b[1my{RESET} │"


def test_table_shrinks_widest_columns_to_fit(monkeypatch):
    monkeypatch.setenv("COLUMNS", "40")
    table = Table()
    table.add_column("Key")
    table.add_column("Description")
    table.add_row("quad9", "Malware blocking, DNSSEC validation, no logging")

    lines = table.render().splitlines()
    assert all(len(line) <= 40 for line in lines)
    assert lines[3:6] == [
        "│ quad9 │ Malware blocking, DNSSEC     │",
        "│       │ validation, no logging       │",
        "└───────┴──────────────────────────────┘",
    ]


def test_table_never_splits_a_word(monkeypatch):
    monkeypatch.setenv("COLUMNS", "10")
    table = Table()
    table.add_column("Host")
    table.add_row("dns.quad9.net")

    assert "│ dns.quad9.net │" in table.render().splitlines()


def test_table_counts_wide_characters_as_two_cells():
    table = Table(show_header=False)
    table.add_column()
    table.add_column()
    table.add_row("日本", "a")
    table.add_row("ab", "b")

    assert table.render().splitlines() == [
        "┌──────┬───┐",
        "│ 日本 │ a │",
        "│ ab   │ b │",
        "└──────┴───┘",
    ]


def test_table_rejects_extra_cells():
    table = Table()
    table.add_column("A")
    with pytest.raises(ValueError, match="2 cells for 1 columns"):
        table.add_row("1", "2")


def test_console_prints_tables(capsys):
    table = Table()
    table.add_column("Backend")
    table.add_row("resolved")
    Console().print(table)

    assert capsys.readouterr().out.splitlines()[3] == "│ resolved │"


# ----------------------------------------------------------------------
# --no-color
# ----------------------------------------------------------------------


@pytest.mark.parametrize(
    ("argv", "expected"),
    [
        (["list"], False),
        (["--no-color", "list"], True),
        (["list", "--no-color"], True),
        (["--no-color", "set", "quad9", "--dry-run"], True),
    ],
)
def test_no_color_before_or_after_the_command(argv, expected):
    assert cli.build_parser().parse_args(argv).no_color is expected


def test_main_applies_no_color_and_resets_it(monkeypatch):
    stream = FakeTTY()
    monkeypatch.setattr("sys.stdout", stream)

    assert cli.main(["list", "--no-color"]) == 0
    assert "\x1b[" not in stream.getvalue()

    stream.seek(0)
    stream.truncate()
    assert cli.main(["list"]) == 0
    assert "\x1b[" in stream.getvalue()


def test_list_output_has_no_leftover_markup(capsys):
    assert cli.main(["list"]) == 0
    out = capsys.readouterr().out
    assert "quad9" in out
    assert "[/" not in out
    assert "\x1b[" not in out  # captured output is not a terminal
