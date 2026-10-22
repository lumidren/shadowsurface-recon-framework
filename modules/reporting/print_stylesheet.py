"""
Print-Optimized Stylesheet Layout for PDF Export
Provides clean media-print CSS styles for printing HTML dashboards directly to high-res PDF.
"""

PRINT_CSS = """
@media print {
    body {
        background: #ffffff !important;
        color: #000000 !important;
        font-size: 11pt;
    }
    .header {
        border-bottom: 2px solid #000000 !important;
    }
    .card {
        background: #f8f9fa !important;
        border: 1px solid #cccccc !important;
        page-break-inside: avoid;
    }
    .badge {
        background: #eeeeee !important;
        color: #000000 !important;
        border: 1px solid #333333;
    }
    button, .interactive-controls {
        display: none !important;
    }
}
"""

def get_print_css() -> str:
    """Returns CSS block for printable reports."""
    return PRINT_CSS
