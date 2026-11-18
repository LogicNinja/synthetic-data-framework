from synthetic_data.retrieval.local_bm25 import LocalBM25Retriever


def test_bm25_retrieves_matching_reference_and_formats_source(tmp_path):
    (tmp_path / "wmi.md").write_text(
        "WmiPrvSE.exe can start a PowerShell child process. T1047.",
        encoding="utf-8",
    )
    (tmp_path / "benign.md").write_text(
        "A log file is created by an application.", encoding="utf-8"
    )
    retriever = LocalBM25Retriever([tmp_path], chunk_chars=300, overlap_chars=0)

    hits = retriever.retrieve("WmiPrvSE PowerShell T1047")
    context = retriever.format_context("WmiPrvSE PowerShell T1047")

    assert hits[0].source.endswith("wmi.md")
    assert "untrusted data" in context
    assert "wmi.md" in context
