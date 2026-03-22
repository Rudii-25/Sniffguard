

import sys
from utils.logger import log
from gui.main_window import start_gui

def main():
    """Main entry point for the SniffGu@rd application."""
    log.info("=======================================")
    log.info("      SniffGu@rd Application Start     ")
    log.info("=======================================")
        
    start_gui()

if __name__ == "__main__":
    main()