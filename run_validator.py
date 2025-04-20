if __name__ == '__main__':
    from framework.config_validator import ConfigValidator
    validator = ConfigValidator()
    if not validator.load():
        print("Failed to load config.")
        exit(1)
    errors = validator.validate()
    if errors:
        print("Config validation failed with errors:")
        for err in errors:
            print(" -", err)
        exit(1)
    print("Config is valid.")