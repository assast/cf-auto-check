import logging
import sys

def setup_logger(name='CFAutoCheck'):
    logger = logging.getLogger(name)
    logger.setLevel(logging.INFO)
    
    # Create console handler
    handler = logging.StreamHandler(sys.stdout)
    handler.setLevel(logging.INFO)
    
    # Create formatter
    formatter = logging.Formatter('[%(asctime)s] [%(levelname)s] %(message)s', datefmt='%Y-%m-%dT%H:%M:%S.000Z')
    handler.setFormatter(formatter)
    
    # Add handler to logger
    if not logger.handlers:
        logger.addHandler(handler)
        
    return logger

logger = setup_logger()
