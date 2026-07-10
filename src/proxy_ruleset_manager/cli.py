from .config import Config, setup_logging
from .pipeline import RuleParser


def main():
    config = Config()
    setup_logging(config.log_file)
    return RuleParser().run()
