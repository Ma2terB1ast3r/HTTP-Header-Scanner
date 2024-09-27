import requests
from rich.console import Console
from rich.table import Table

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
        results['missingHeaders'][header] = ''

    # Check which of the present headers have the best practice value
    bestPracticeHeaders = {}
    for header in presentHeaders:
        if requiredHeaders[header] == responseHeaders[header]:
            results['bestPracticeHeaders'][header] = responseHeaders[header]
        else:
            results['notBestPracticeHeaders'][header] = responseHeaders[header]

    return results

def outputResults(results, requiredHeaders):
    '''Outputs the results in a table using the rich library.
    '''
    # Generate Tables
    with console.status("[bold green]Generating report...") as status:
        # Best Practice Headers Table
        bp_table = Table(title="Best Practice Headers")
        bp_table.add_column("Header")
        bp_table.add_column("Value")
        bp_table.add_column("Expected Value")
        for header, value in results['bestPracticeHeaders'].items():
            bp_table.add_row(header, value, requiredHeaders[header], style="green")

        # Not Best Practice Headers Table
        nbp_table = Table(title="Not Best Practice Headers")
        nbp_table.add_column("Header")
        nbp_table.add_column("Value")
        nbp_table.add_column("Expected Value")
        for header, value in results['notBestPracticeHeaders'].items():
            nbp_table.add_row(header, value, requiredHeaders[header], style="yellow")

        # Missing Headers Table
        mi_table = Table(title="Missing Headers")
        mi_table.add_column("Header")
        mi_table.add_column("Expected Value")
        for header, value in results['missingHeaders'].items():
            mi_table.add_row(header, requiredHeaders[header], style="red")

        console.log("Report generated")

    # Print tables
    console.print(bp_table)
    console.print(nbp_table)
    console.print(mi_table)

    # Print count of each type of header
    console.print(f"Best Practice Headers: {len(results['bestPracticeHeaders'])}", style="green")
    console.print(f"Not Best Practice Headers: {len(results['notBestPracticeHeaders'])}", style="yellow")
    console.print(f"Missing Headers: {len(results['missingHeaders'])}", style="red")


def main():
    # Init rich console
    global console
    console = Console()

    # Fetch latest best practices
    with console.status("[bold green]Fetching latest best practices...") as status:
        requiredHeaders = fetchLatestPractices()
        console.log("Fetched latest best practices")

    # Fetch target headers
    with console.status("[bold green]Fetching headers for target...") as status:
        targetHeaders = requests.get(URL).headers
        console.log("Fetched target headers")

    # Check target headers against best practices
    with console.status("[bold green]Analysing headers...") as status:
        results = analyseHeaders(requiredHeaders, targetHeaders)
        console.log("Headers analysed")

    # Output results
    outputResults(results, requiredHeaders)

if __name__ == "__main__":
    main()
