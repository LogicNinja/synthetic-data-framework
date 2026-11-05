
"""WMI spawning PowerShell attack scenario."""

from synthetic_data.simulator.scenario_runner import ScenarioContext


def run_wmi_powershell(context: ScenarioContext) -> None:
    """Simulate WMI launching a PowerShell child process."""

    # Step 1: Start the WMI provider process.
    context.actions.start_process(
        host_id=context.host.host_id,
        user_id=context.user.user_id,
        image=r"C:\Windows\System32\WmiPrvSE.exe",
        command_line=r"C:\Windows\System32\WmiPrvSE.exe",
        process_id="1000",
        original_file_name="WmiPrvSE.exe",
        timestamp="2026-01-01T10:00:00+00:00",
        technique_labels=["T1047"],
    )

    # Step 2: WMI launches a PowerShell child process.
    context.actions.spawn_child(
        parent_process_id="1000",
        image=(
            r"C:\Windows\System32\WindowsPowerShell"
            r"\v1.0\powershell.exe"
        ),
        command_line=(
            "powershell.exe -NoProfile "
            "-ExecutionPolicy Bypass -Command Get-Process"
        ),
        process_id="1001",
        original_file_name="PowerShell.EXE",
        timestamp="2026-01-01T10:00:01+00:00",
        technique_labels=["T1059.001"],
    )

