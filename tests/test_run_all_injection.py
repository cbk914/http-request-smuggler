"""Regression tests for the command injection in run-all.py.

The original build_command produced a single interpolated string and handed it
to subprocess with shell=True:

    command = f"python3 http-request-smuggler.py -t {tech} -u https://{url}"
    process = subprocess.Popen(command, shell=True, ...)

Every line of targets.txt therefore became shell source. The tests below pin
the three properties that close that hole:

  1. a poisoned targets.txt line cannot execute,
  2. target validation rejects shell metacharacters,
  3. the command is built in list form with the target as one argv element.

No external host is ever contacted: the only payload used writes a sentinel
into a pytest tmp_path, and the fixed runner rejects the line before it can
build a command.
"""

import sys

import pytest


def _payload_for(sentinel):
    """A targets.txt line whose tail would run if a shell ever saw it.

    ``&`` is the command separator in both cmd.exe and POSIX sh, so this
    executes on either platform.
    """
    return (
        "example.com & python -c "
        "\"import pathlib; pathlib.Path(r'" + str(sentinel) + "').write_text('pwned')\""
    )


def test_poisoned_target_line_does_not_execute(run_all, tmp_path, monkeypatch):
    """A single poisoned line in targets.txt must not reach a shell."""
    sentinel = tmp_path / "pwned.txt"
    poisoned = _payload_for(sentinel)

    (tmp_path / "targets.txt").write_text(poisoned + "\n", encoding="utf-8")
    monkeypatch.chdir(tmp_path)

    # main() is the one entry point shared by the original and the fixed
    # runner, so this same test discriminates between the two trees.
    run_all.main()

    assert not sentinel.exists(), (
        "command injection: the poisoned targets.txt line executed and created "
        + str(sentinel)
    )


def test_validator_rejects_shell_metacharacters(run_all):
    for hostile in [
        "example.com; whoami",
        "example.com & whoami",
        "example.com | whoami",
        "example.com && whoami",
        "example.com`whoami`",
        "example.com$(whoami)",
        "example.com\nwhoami",
        "example.com whoami",
        "$(curl http://attacker.example)",
        "",
        "   ",
    ]:
        with pytest.raises(ValueError):
            run_all.validate_target(hostile)


def test_validator_accepts_ordinary_targets(run_all):
    for good in ["example.com", "sub.example.co.uk", "10.0.0.5", "localhost", "[::1]"]:
        scheme, host = run_all.validate_target(good)
        assert scheme == "https"
        assert host == good


def test_validator_strips_scheme_and_path(run_all):
    assert run_all.validate_target("http://example.com/admin") == ("http", "example.com")
    assert run_all.validate_target("https://example.com") == ("https", "example.com")


def test_build_command_is_list_form(run_all):
    command = run_all.build_command("example.com", "CLTE")

    assert isinstance(command, list), "argv must be a list, not a shell string"
    assert all(isinstance(part, str) for part in command)

    # No shell metacharacter survives anywhere in the argv.
    joined = " ".join(command)
    for char in (";", "|", "&", "`", "$", "\n"):
        assert char not in joined

    # The URL is exactly one element, so a hostile target can never split out.
    assert command[-1] == "https://example.com"

    # The interpreter is the one actually running this code, not a hardcoded
    # "python3" that does not exist under that name on Windows.
    assert command[0] == sys.executable


def test_build_command_never_interpolates_hostile_target(run_all):
    hostile = "example.com; touch /tmp/pwned"

    # Validation happens while building the command, so the hostile string can
    # never be assembled into an argv at all.
    with pytest.raises(ValueError):
        run_all.build_command(hostile, "CLTE")


def test_read_urls_skips_comments_and_blanks(run_all, tmp_path):
    target_file = tmp_path / "targets.txt"
    target_file.write_text(
        "# a comment\n\n  \nexample.com\n\n#another\nexample.org\n", encoding="utf-8"
    )

    assert run_all.read_urls(str(target_file)) == ["example.com", "example.org"]


def test_run_command_rejects_poisoned_target(run_all, tmp_path):
    """run_command must refuse before it constructs any process."""
    with pytest.raises(ValueError):
        run_all.run_command("example.com & whoami", "CLTE")