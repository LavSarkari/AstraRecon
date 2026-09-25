"""Live Scan Dashboard and Status Panel."""

from astrarecon.cli.ui.components import (
    CompletionSummaryView,
    StatusPanel,
)


class LiveScanView(StatusPanel):
    """Backwards-compatible wrapper around StatusPanel."""

    def __init__(self, target: str, workflow_id: str, node_ids: list[str]):
        super().__init__(target=target, node_ids=node_ids, workflow_id=workflow_id)
