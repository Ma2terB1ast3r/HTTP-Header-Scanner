import requests

requiredHeaders = {}

URL = ''

def analyseHeaders(requiredHeaders, responseHeaders):
    '''Checks which of the 'requiredHeaders' are in the 'responseHeaders'.
    '''
    # Find the headers that are present in the header
    presentHeaders = requiredHeaders.keys() & responseHeaders.keys()
    print("Present Headers: ")
    print(presentHeaders)

    # Find the headers that aren't present
    missingHeaders = requiredHeaders.keys() - responseHeaders.keys()
    print("Missing Headers: ")
    print(missingHeaders)

    # Check which of the present headers have the best practice value
    bestPracticeHeaders = {}
    for header in presentHeaders:
        if requiredHeaders[header] == responseHeaders[header]:
            bestPracticeHeaders[header] = True
        else:
            bestPracticeHeaders[header] = False
    print("Best Practice Headers: ")
    print(bestPracticeHeaders)

def main():
    response = requests.get(URL)
    analyseHeaders(requiredHeaders, response.headers)
    # print(response.headers)

if __name__ == "__main__":
    main()
