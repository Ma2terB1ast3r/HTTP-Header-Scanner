import requests

requiredHeaders = {}

URL = ''

def fetchLatestPractices():
    '''Fetches the latest HTTP header best practices from the OWASP secure headers project. https://owasp.org/www-project-secure-headers/
    '''
    OWASP_HEADERS = requests.get('https://owasp.org/www-project-secure-headers/ci/headers_add.json').json()

    headers = {}
    for key in OWASP_HEADERS['headers']:
        headers[key['name']] = key['value']

    return headers

def analyseHeaders(requiredHeaders, responseHeaders):
    '''Checks which of the 'requiredHeaders' are in the 'responseHeaders'.
    '''
    # Init results object
    results = {
        'missingHeaders':{
        },
        'bestPracticeHeaders':{
        },
        'notBestPracticeHeaders':{
        }
    }

    # Find the headers that are present in the header
    presentHeaders = requiredHeaders.keys() & responseHeaders.keys()

    # Find the headers that aren't present
    missingHeaders = requiredHeaders.keys() - responseHeaders.keys()
    for header in missingHeaders:
        results['missingHeaders'][header] = requiredHeaders[header]

    # Check which of the present headers have the best practice value
    bestPracticeHeaders = {}
    for header in presentHeaders:
        if requiredHeaders[header] == responseHeaders[header]:
            results['bestPracticeHeaders'][header] = requiredHeaders[header]
        else:
            results['notBestPracticeHeaders'][header] = requiredHeaders[header]

    return results

def outputResults(results):
    '''Outputs the results.
    '''
    print("Missing Headers: ")
    print(results['missingHeaders'])
    print("Best Practice Headers: ")
    print(results['bestPracticeHeaders'])
    print("Not Best Practice Headers: ")
    print(results['notBestPracticeHeaders'])

def main():
    # Fetch latest best practices
    requiredHeaders = fetchLatestPractices()

    # Fetch target headers
    targetHeaders = requests.get(URL).headers
    # print("Target Headers: ")
    # print(targetHeaders)

    # Check target headers against best practices
    results = analyseHeaders(requiredHeaders, targetHeaders)

    # Output results
    outputResults(results)

if __name__ == "__main__":
    main()
