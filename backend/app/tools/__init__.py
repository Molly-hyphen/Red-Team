from typing import Dict, Optional, List
from app.tools.base_tool import SecurityTool, ToolObservation
from app.tools.http_tool import HTTPTool
from app.tools.recon_tool import ReconTool
from app.tools.scanner_tool import ScannerTool
from app.tools.source_analysis_tool import SourceAnalysisTool
from app.tools.terminal_tool import TerminalTool
from app.tools.browser_tool import BrowserTool, ScreenshotTool, ProxyTool

class ToolRegistry:
    def __init__(self):
        self._tools: Dict[str, SecurityTool] = {}
        self.register(HTTPTool())
        self.register(ReconTool())
        self.register(ScannerTool())
        self.register(SourceAnalysisTool())
        self.register(TerminalTool())
        self.register(BrowserTool())
        self.register(ScreenshotTool())
        self.register(ProxyTool())

    def register(self, tool: SecurityTool):
        self._tools[tool.name] = tool

    def get_tool(self, name: str) -> Optional[SecurityTool]:
        return self._tools.get(name)

    def list_tools(self) -> List[Dict[str, str]]:
        return [
            {
                "name": t.name,
                "description": t.description,
                "category": t.category
            }
            for t in self._tools.values()
        ]

tool_registry = ToolRegistry()
