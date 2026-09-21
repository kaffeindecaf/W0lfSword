"""Wolf scramble animation frame tests (ported from W0lfSword scramble_wolf)."""

import random

from main import SCRAMBLE_CHARS, _wolf_art_lines, wolf_scramble_frame


def test_art_lines_are_stripped_and_nonempty():
    lines = _wolf_art_lines()
    assert len(lines) >= 10
    assert all(not ln.endswith("\n") for ln in lines)
    assert any("$" in ln for ln in lines)  # wolf body chars present


def test_scramble_keeps_spaces_and_line_length():
    art = _wolf_art_lines()
    rng = random.Random(7)
    frames = [wolf_scramble_frame(art, p, rng) for p in (0, 25, 50, 75, 99)]
    for fr in frames:
        assert len(fr) == len(art)
        for src, dst in zip(art, fr):
            assert len(dst) == len(src)
            for a, b in zip(src, dst):
                if a == " ":
                    assert b == " "  # spaces never scramble


def test_scramble_progress_0_is_full_random():
    art = _wolf_art_lines()
    rng = random.Random(1)
    frame = wolf_scramble_frame(art, 0, rng)
    for src, dst in zip(art, frame):
        for a, b in zip(src, dst):
            if a != " ":
                assert b in SCRAMBLE_CHARS


def test_scramble_progress_100_is_settled_art():
    art = _wolf_art_lines()
    frame = wolf_scramble_frame(art, 100, random.Random(2))
    assert frame == art


def test_scramble_is_deterministic_for_fixed_seed():
    art = _wolf_art_lines()
    a = wolf_scramble_frame(art, 40, random.Random(99))
    b = wolf_scramble_frame(art, 40, random.Random(99))
    assert a == b


def test_higher_progress_settles_more_chars_on_average():
    # each frame re-rolls every char independently (as in the bash original),
    # so higher progress only guarantees more settled chars statistically
    art = _wolf_art_lines()
    non_space = sum(1 for ln in art for ch in ln if ch != " ")

    def mean_settled(p: int, trials: int = 120) -> float:
        total = 0
        for t in range(trials):
            frame = wolf_scramble_frame(art, p, random.Random(t))
            total += sum(1 for src, dst in zip(art, frame) for a, b in zip(src, dst) if a != " " and a == b)
        return total / trials

    low, high = mean_settled(10), mean_settled(90)
    assert high > low
    assert high > non_space * 0.85  # p=90 settles ~90% of chars
    assert low < non_space * 0.20   # p=10 settles ~10% of chars
