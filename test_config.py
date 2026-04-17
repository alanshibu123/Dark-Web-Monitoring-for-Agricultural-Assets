from config.settings import config_manager

agriculture_terms = config_manager.get_keywords('agriculture_terms')

print(agriculture_terms)