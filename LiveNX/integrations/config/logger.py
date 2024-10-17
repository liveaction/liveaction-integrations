import logging
import logging.handlers as handlers
import os
import sys
from utils.constants import LOG_FOLDER


class LoggerFilter(object):
    """
    Filter the log based on level(DEBUG, ERROR, INFO, CRITICAL, WARN)
    """
    def __init__(self, level) -> None:
        self.__level = level
    
    def filter(self, logRecord):
        return logRecord.levelno <= self.__level
    
def setup_logger(name, logstdout = False, loglevel = logging.INFO) -> logging.Logger:

    ## Check if Log folder exist if not create in working directory

    if logstdout == True:
        logging.basicConfig(stream=sys.stdout, level=loglevel)
        return logging.getLogger(name)

    if not os.path.isdir(LOG_FOLDER):
        os.mkdir(LOG_FOLDER)
        
    logging.basicConfig(filename=f'{LOG_FOLDER}/livenx-integrations.log', level=loglevel)
    formatter = logging.Formatter('[%(asctime)s %(name)s %(module)s:%(lineno)s],%(levelname)-8s:%(message)s')

    infoLogHandler = handlers.TimedRotatingFileHandler(f'{LOG_FOLDER}/livenx-integrations.log', when="midnight")
    infoLogHandler.prefix = "%Y%m%d"
    infoLogHandler.setLevel(loglevel)
    infoLogHandler.setFormatter(formatter)
    infoLogHandler.addFilter(LoggerFilter(loglevel))
    # logging.basicConfig(filename='livenx-integrations.log', level=logging.INFO)

    logger = logging.getLogger(name)
    logger.addHandler(infoLogHandler)

    return logger