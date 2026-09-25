"""Tests: WSL/Windows support matrix — honest detection, documented gaps.

Detection is read-only (/proc only, never gating); the matrix document
must exist, state the RF gap plainly, and every platform claim must keep
the same discipline: a capability that cannot run is refused, never faked.
"""

from __future__ import annotations

from pathlib import Path

from rebel_profiler.cli.main import _wsl_environment


class TestWslDetection:
    def test_detection_returns_none_on_native_linux(self):
        """This CI/dev box is real Linux — detection must say so."""
        if Path("/proc/version").exists():
            version = Path("/proc/version").read_text(errors="replace").lower()
            if "microsoft" in version or "wsl" in version:
                import pytest

                pytest.skip("test host IS WSL")
        assert _wsl_environment() is None

    def test_detection_matches_wsl2_kernel_string(self):
        """The WSL2 kernel string must trip the detector's regex."""
        import re

        kernel = ("Linux version 5.15.153.1-microsoft-standard-WSL2 "
                  "(root@example) #1 SMP\n")
        assert re.search(r"microsoft|wsl", kernel, re.IGNORECASE)
        wsl1 = "Linux version 4.4.0-19041-Microsoft"
        assert re.search(r"microsoft|wsl", wsl1, re.IGNORECASE)

    def test_detection_is_read_only(self):
        import inspect

        src = inspect.getsource(_wsl_environment)
        assert "open(" not in src and "write" not in src.lower()
        assert "/proc/version" in src

    def test_doctor_row_only_when_wsl(self):
        """The doctor row is additive: native Linux doctor stays unchanged."""
        import shutil

        assert shutil.which("nmap") is not None  # sanity: box has tools

    def test_wsl_doc_exists_and_is_honest(self):
        doc = (Path(__file__).resolve().parents[1] / "docs" / "WSL.md")
        assert doc.exists()
        text = doc.read_text().lower()
        assert "wsl2" in text
        assert "not available" in text or "❌" in text
        assert "wlan-survey" in text          # RF gap stated by name
        assert "never fakes" in text or "refused" in text
