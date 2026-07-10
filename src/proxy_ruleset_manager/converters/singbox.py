"""Sing-box converter helpers."""

from ..utils import run_command


def convert_adguard_to_singbox(input_path, output_path):
    return run_command(
        [
            "sing-box",
            "rule-set",
            "convert",
            "--type",
            "adguard",
            "--output",
            output_path,
            input_path,
        ],
        f"转换 AdGuard 规则 {input_path}",
    )


__all__ = ["convert_adguard_to_singbox"]
