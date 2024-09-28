import requests
import sys
from rich.console import Console
from rich.table import Table
from rich.panel import Panel

requiredHeaders = {}

URL = ''

options = {
    'verbose': False
}

def fetchLatestConfigProposal():
    '''Fetches the latest 'Configuration Proposal' from the OWASP secure headers project. https://owasp.org/www-project-secure-headers/
    '''
    OWASP_HEADERS = requests.get('https://owasp.org/www-project-secure-headers/ci/headers_add.json').json()
    headers = {}
    for key in OWASP_HEADERS['headers']:
        headers[key['name']] = key['value']

    return headers

def fetchLatestDisclosureHeaders():
    '''Fetches the latest headers that disclose information from the OWASP secure headers project. https://owasp.org/www-project-secure-headers/
    '''
    OWASP_HEADERS = requests.get('https://owasp.org/www-project-secure-headers/ci/headers_remove.json').json()
    headers = OWASP_HEADERS['headers']

    return headers

def analyseHeaders(requiredHeaders, responseHeaders):
    '''Checks which of the 'requiredHeaders' are in the 'responseHeaders'.
    '''
    # Init results object
    results = {
        'presentHeaders': {
        },
        'missingHeaders':{
        },
        'bestPracticeHeaders':{
        },
        'notBestPracticeHeaders':{
        }
    }

    # If the response headers are in dictionary format (used for config proposal)
    if type(responseHeaders) == 'dict':
        # Find the headers that are present in the header
        presentHeaders = requiredHeaders.keys() & responseHeaders.keys()
        for header in presentHeaders:
            results['presentHeaders'][header] = responseHeaders[header]

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
    # If the response headers are in list format (used for disclosure prevention)
    else:
        # Find the headers that are present in the header
        presentHeaders = requiredHeaders & responseHeaders.keys()
        for header in presentHeaders:
            results['presentHeaders'][header] = responseHeaders[header]

        # Find the headers that aren't present
        missingHeaders = requiredHeaders - responseHeaders.keys()
        for header in missingHeaders:
            results['missingHeaders'][header] = ''

    return results

def outputConfigProposalResults(results, requiredHeaders):
    '''Outputs the configuration proposal results in a table using the rich library.
    '''
    # Generate Tables
    with console.status("[bold green]Generating Report...") as status:
        # If verbose is enabled, print all headers
        if options['verbose']:
            # Best Practice Headers Table
            bp_table = Table(title="Best Practice Headers")
            bp_table.add_column("Header")
            bp_table.add_column("Value")
            bp_table.add_column("Expected Value")
            for header, value in results['bestPracticeHeaders'].items():
                bp_table.add_row(header, value, requiredHeaders[header], style="green")

        # Not Best Practice Headers Table
        if len(results['notBestPracticeHeaders']) > 0 or options['verbose']:
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

        console.log("Configuration Proposal Report generated")

    # Print tables
    if options['verbose']:
        console.print(bp_table)
    if len(results['notBestPracticeHeaders']) > 0 or options['verbose']:
        console.print(nbp_table)
    console.print(mi_table)

    # Print count of each type of header
    console.print(f"Best Practice Headers: {len(results['bestPracticeHeaders'])}", style="green")
    console.print(f"Not Best Practice Headers: {len(results['notBestPracticeHeaders'])}", style="yellow")
    console.print(f"Missing Headers: {len(results['missingHeaders'])}", style="red")


def outputInfoDisclosureResults(results, requiredHeaders):
    '''Outputs the information disclosure results in a table using the rich library.
    '''
    # Generate Tables
    with console.status("[bold green]Generating Information Disclosure Report...") as status:
        # Present Headers Table
        pe_table = Table(title="Present Headers")
        pe_table.add_column("Header")
        pe_table.add_column("Value")
        for header, value in results['presentHeaders'].items():
            pe_table.add_row(header, value, style="red")

        # If verbose is enabled, print all headers
        if options['verbose']:
            # Missing Headers Table
            mi_table = Table(title="Missing Headers")
            mi_table.add_column("Header")
            for header, value in results['missingHeaders'].items():
                mi_table.add_row(header, style="green")

        console.log("Information Disclosure Report generated")

    # Print tables
    console.print(pe_table)
    if options['verbose']:
        console.print(mi_table)

    # Print count of each type of header
    console.print(f"Present Headers: {len(results['presentHeaders'])}", style="red")
    console.print(f"Missing Headers: {len(results['missingHeaders'])}", style="green")

# Scan the target URL for configuration headers
def configScan(URL):
    '''Performs a scan of the target URL for configuration headers.
    '''
    # Fetch latest best practices
    with console.status("[bold green]Fetching latest best practices...") as status:
        configProposedHeaders = fetchLatestConfigProposal()
        console.log("Fetched latest best practices")

    # Fetch target headers
    with console.status("[bold green]Fetching headers for target...") as status:
        targetHeaders = requests.get(URL).headers
        console.log("Fetched target headers")

    # Check target headers against best practices
    with console.status("[bold green]Analysing headers...") as status:
        configResults = analyseHeaders(configProposedHeaders, targetHeaders)
        console.log("Configuration of headers analysed")

    # Output results
    outputConfigProposalResults(configResults, configProposedHeaders)

# Scan the target URL for information disclosure headers
def disclosureScan(URL):
    '''Performs a scan of the target URL for information disclosure headers.
    '''
    # Fetch latest best practices
    with console.status("[bold green]Fetching latest best practices...") as status:
        infoDisclosureHeaders = fetchLatestDisclosureHeaders()
        console.log("Fetched latest best practices")

    # Fetch target headers
    with console.status("[bold green]Fetching headers for target...") as status:
        targetHeaders = requests.get(URL).headers
        console.log("Fetched target headers")

    # Check target headers against best practices
    with console.status("[bold green]Analysing headers...") as status:
        disclosureResults = analyseHeaders(infoDisclosureHeaders, targetHeaders)
        console.log("Information disclosure headers analysed")

    # Output results
    outputInfoDisclosureResults(disclosureResults, infoDisclosureHeaders)

# Full scan of the target URL
def fullScan(URL):
    '''Performs a full scan of the target URL.
    '''
    # Fetch latest best practices
    with console.status("[bold green]Fetching latest best practices...") as status:
        configProposedHeaders = fetchLatestConfigProposal()
        infoDisclosureHeaders = fetchLatestDisclosureHeaders()
        console.log("Fetched latest best practices")

    # Fetch target headers
    with console.status("[bold green]Fetching headers for target...") as status:
        targetHeaders = requests.get(URL).headers
        console.log("Fetched target headers")

    # Check target headers against best practices
    with console.status("[bold green]Analysing headers...") as status:
        configResults = analyseHeaders(configProposedHeaders, targetHeaders)
        console.log("Configuration of headers analysed")
        disclosureResults = analyseHeaders(infoDisclosureHeaders, targetHeaders)
        console.log("Information disclosure headers analysed")

    # Output results
    outputConfigProposalResults(configResults, configProposedHeaders)
    outputInfoDisclosureResults(disclosureResults, infoDisclosureHeaders)

# Print help menu
def helpMenu():
    '''Displays the help menu.
    '''
    helpPanel = Panel.fit('''[bold]Description:[/bold]
A simple script to scan a URL for security headers. The script will compare the headers of the target URL with the latest best practices from the OWASP Secure Headers project.
By default, the script will perform a full scan of the target URL and output the headers that should be changed to improve security. To show all headers, use the -v or --verbose flag.

[bold]Simple Usage:[/bold]
python scanner.py -u [bold]URL[/bold]

[bold]Options:[/bold]
-c, --config        Perform a scan of the target URL for configuration headers
-d, --disclosure    Perform a scan of the target URL for information disclosure headers
-f, --full          Perform a full scan of the target URL
-h, --help          Display this help menu
-u, --url [bold]URL[/bold]       The URL to scan
-v, --verbose       Display verbose output

[bold]Examples:[/bold]
python scanner.py -u https://example.com            Perform a full scan of the target URL
python scanner.py -u https://example.com -c         Perform a scan of the target URL for configuration headers
python scanner.py -u https://example.com -d -v      Perform a scan of the target URL for information disclosure headers and display all headers''', title="Help Menu:", title_align="left")

    console.print(helpPanel)

def main():
    # Init rich console
    global console
    console = Console()
    global URL

    # Check if no arguments are passed default to full scan with local URL
    if len(sys.argv) == 1:
        fullScan()
        return 0

    # If invalid arguments are passed
    valid_args = ['-c', '--config', '-d', '--disclosure', '-f', '--full', '-h', '--help', '-u', '--url', '-v', '--verbose']
    for arg in sys.argv[1:]:
        if arg.startswith('-') and arg not in valid_args:
            console.print(f"[bold red]Error:[/bold red] Invalid argument: {arg}")
            console.print("Use -h or --help for help menu")
            return 0

    # Show help menu
    if '-h' in sys.argv:
        helpMenu()
        return 0

    # Set options
    if '-v' in sys.argv or '--verbose' in sys.argv:
        options['verbose'] = True

    # Set URL
    if '-u' in sys.argv:
        URL = sys.argv[sys.argv.index('-u')+1]
        if len(sys.argv) == 3:
            console.print("No scan type specified, defaulting to full scan")
            console.print(URL)
            fullScan(URL)
            return 0
    elif '--url' in sys.argv:
        URL = sys.argv[sys.argv.index('--url')+1]
        if len(sys.argv) == 3:
            console.print("No scan type specified, defaulting to full scan")
            console.print(URL)
            fullScan(URL)
            return 0

    # Check for scan type
    if '-f' in sys.argv or '--full' in sys.argv:
        fullScan(URL)
        return 0
    if '-c' in sys.argv or '--config' in sys.argv:
        configScan(URL)
        return 0
    if '-d' in sys.argv or '--disclosure' in sys.argv:
        disclosureScan(URL)
        return 0

    # Catch all if nothing happened (shouldn't be reached)
    console.print("[bold red]Error:[/bold red] Unknown error occured")
    console.print("Use -h or --help for help menu")
    return 1

if __name__ == "__main__":
    main()