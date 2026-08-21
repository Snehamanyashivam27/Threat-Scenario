from rag.utils.progress import report_progress


def test_report_progress_prints_percent(capsys):
    report_progress("Embedding chunks into Chroma", 0, 100)
    report_progress("Embedding chunks into Chroma", 50, 100)
    report_progress("Embedding chunks into Chroma", 100, 100)
    output = capsys.readouterr().out
    assert "0/100 (0%)" in output
    assert "50/100 (50%)" in output
    assert "100/100 (100%)" in output
