# HTTP Header Scanner

A simple script that scans the HTTP response headers to ensure they meet the OWASP Secure Headers Project best practices ([https://owasp.org/www-project-secure-headers/](https://owasp.org/www-project-secure-headers/)). It should be noted that depending on the application, some headers may not be applicable or may need to be adjusted for certain functionality. The 'Clear-Site-Data' will rarely be shown as meeting the best practice as it is typically only used for clearing data on logout.

## Features

- Fetches the latest best practices from the OWASP Secure Headers Project
- Scans the HTTP response headers to ensure they are configured following the current best practices
- Scans for headers that unnecessarily expose information
- Generates a report of the results

## Dependencies

- [Python 3](https://www.python.org/downloads/)
- [requests](https://pypi.org/project/requests/)
- [rich](https://github.com/Textualize/rich)

## To Do

- [X] Check for headers that unnecessarily expose information
- [ ] Use command line arguments to specify the URL
- [ ] Check multiple URLs at once
- [ ] Excluded headers (e.g. 'Clear-Site-Data')
- [ ] Mutli-threading?
