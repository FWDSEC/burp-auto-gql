# Auto GraphQL Scanner (aka Auto GQL)

**Auto GQL** *(currently in Beta)* is a Burp Suite extension that automates the process of vulnerability hunting in GraphQL APIs. It does this using only the URL to the GraphQL endpoint (and option configurations) to make an Introspection Query, turn that into all possible API requests, find possible injection points for payloads, and handing them off to Active Scanner. Prior to this, Burp's Active Scanner did not know where to put payloads for GraphQL requests. It was a dog's breakfast. This plugin "teaches" it where to put the payloads, AND creates the requests for you, so you don't have to click around in the proxy to try and get every combination.
## Installation:
### Prerequisites
1. This plugin uses the Active Scanner, which is a Burp **Pro** feature.
2. Download Jython Standalone: https://www.jython.org/download.html
3. Open Burp > Extender > Options > Python Environment
4. Select the Jython jar
### Installation Steps
4. Open Burp > Extender > Extensions > Add
5. Extension Type: Python
6. Select file: burp-ext.py

## Usage:
1. Select the **Auto GQL** tab in Burp
2. Enter the URL for the GraphQL endpoint.
   - *Example:* For [DVGA](https://github.com/dolevf/Damn-Vulnerable-GraphQL-Application) the URL is `http://localhost:5013.com/graphql`
3. Add any custom headers that might be required to make queries to the target.
   - *Examples*
     - An *Authorization* header with bearer token 
     - A browser *User-Agent*
4. Click the **Fetch Queries** button to run the Introspection query and automatically parse the schema into all possible queries. This can take up to a minute.
   - TODO: add a little progress/loading animation and an error message if the URL is unreachable or malformed.
   - For now just wait a few seconds. If it doesn't work after a minute, check that the URL is correct.
   - Ensure that "Intercept" is turned **off** on the proxy, because the query is run through the proxy so that you can keep a record of it in the logger.
5. Use the checkboxes to select the queries to include in the Active Scan.
   - The extension will automitcally preselect items that have insertion/injection points for the Active Scanner to add payloads to.
   - For the first run, I recommend deselecting any Mutations that will delete data. The scanner is not smart enough to sequence requests with creation first and deletion second, so it might try to run deletion requests multiple times consecutively. You'll get false negatives on some payloads because there wasn't actually any data in the API to try and delete after the first deletion request.
6. Click the **Run Scan** button to begin the Active Scan.
7. View the progress by going to the Dashboard tab in Burp and expanding the "Extension driven active audit"

## Debug:
1. Run Burp using the terminal. (Example is for MacOS) `java -jar -Xmx1g "/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar"`
2. Add `pdb.set_trace()` anywhere you want a breakpoint.
3. Go to Burp > Extender > Add and select burp-ext.py

## To Do:
1. Separate into multiple files, and add build step to unify it back to one. (Burp requires that it be one file)
2. Search filter for queries.
3. Allow for user to manually alter injection points visually.
4. Allow for importing a Schema file as an alternative option to Introspection.
5. Allow for payload transformations (base64, etc.)
6. Maybe convert the whole thing to Java? I picked Python because Burp supports it, and I use it more regularly than Java. Plus all the Python libraries, right? Turns out this was not the best route. Burp *supports* Python, but is written in Java, so all Python support is due to Jython. This requires that the plugin be built in Python2, can't use external libraries (without some extra work from the end user), and has all sorts of fun data type issues that require detours to the Jython documentation. Not to mentinon that it all has to be in one file, which means having to write a Makefile or some other build step. Using Java would solve all those problems, plus the Burp documentation is all geared towards it. Let my toiling save you from your own. Write your Burp extension in Java.

## Acknowledgements
1. The transformation on Introspection response, into requests comes from the wonderful **inQL** extension for Burp. For this reason I have included their Apache license. My plan is to eventually implement my own version of this. Not because it isn't awesome, or because I'm afraid of losing street cred, but because I have some specific needs that will eventually require me to rewrite it. Plus it's fun to do it yourself!
2. Other Burp extensions were helpful references when trying to work out issues that have weak documentation. Some notable ones are **Autorize** and **Logger++**.

## Credits
Author: Jared Meit (baron)
 - Email: j.meit@fwdsec.com
 - Twitter: @jaredmeit
