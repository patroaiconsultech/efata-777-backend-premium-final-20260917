from orkio_v2.services.realtime_segmenter import SentenceSegmenter


def test_emits_first_sentence_as_soon_as_terminal_punctuation_arrives():
    segmenter = SentenceSegmenter()
    assert segmenter.push("Olá, Daniel. A segunda") == ["Olá, Daniel."]
    assert segmenter.flush() == ["A segunda"]


def test_does_not_split_decimal_or_url_on_internal_periods():
    segmenter = SentenceSegmenter()
    assert segmenter.push("Use 3.14 e https://patro.ai/docs agora. Próximo") == [
        "Use 3.14 e https://patro.ai/docs agora."
    ]


def test_does_not_split_common_abbreviation():
    segmenter = SentenceSegmenter()
    assert segmenter.push("Fale com o Dr. Daniel amanhã. Depois") == [
        "Fale com o Dr. Daniel amanhã."
    ]


def test_flush_returns_remaining_text_without_empty_segments():
    segmenter = SentenceSegmenter()
    assert segmenter.push("   ") == []
    assert segmenter.flush() == []
    segmenter.push("Uma resposta sem pontuação")
    assert segmenter.flush() == ["Uma resposta sem pontuação"]


def test_long_text_is_split_only_at_word_boundary():
    segmenter = SentenceSegmenter(max_chars=80)
    first = segmenter.push("palavra " * 20)
    assert first
    assert all(not part.endswith("palavr") for part in first)
    assert all(len(part) >= 80 for part in first[:-1])
