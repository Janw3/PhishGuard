import pandas as pd

from scripts.build_generic_words import document_share, generic_words


def test_document_share_counts_each_text_once():
    shares = document_share(pd.Series(["it it it", "it is", "nothing"]))
    assert shares["it"] == 2 / 3


def test_generic_words_need_to_be_common_in_both_classes():
    df = pd.DataFrame(
        {
            "label": [0, 0, 1, 1],
            "text": ["it is lunch", "it rains", "it is a lottery", "verify it lottery"],
        }
    )
    words = generic_words(df, min_share=0.5)
    assert "it" in words  # common in both classes
    assert "lottery" not in words  # common only in phishing: informative, keep it
    assert "lunch" not in words
