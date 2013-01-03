#!/usr/bin/python
import sys
import signal
import logging
import daemon
import sniffer

class Service(daemon.Daemon):
    """

        Usage:
            service = Service(options)
            service.run() # Interactive

            service = Service(options)
            service.start() # Daemon
    """

    def __init__(self, options):
        """
            Inits daemon.
        """
        daemon.Daemon.__init__(self, options.pidfile)
        self.options = options

    def run(self):
        """
            Main event loop.
        """
        logging.info("Starting service.")
        # Signal handler
        def signal_handler(signum, frame):
            """
                Terminates child processes.
            """
            logging.info("Stopping service.")
            try:
                sys.exit(0)
            except (OSError, AttributeError):
                pass

        signal.signal(signal.SIGINT, signal_handler)
        sniffer.capture_process(self.options)
