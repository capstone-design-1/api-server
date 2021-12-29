import validators

def validate_url_check(url):
    return validators.url(url)