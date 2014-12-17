from logging import config as logging_config


def setup_logging(default_logger='resources/logging.yaml'):
    """
    Calling this method from any module will configure loggers using the python logging
    infrastructure. please see resources/logging.yaml for details of the handlers.
    """
    logging_config.dictConfig(default_logger)
