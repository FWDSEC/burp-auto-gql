# Burp Plugin: Auto GraphQL Scanner (aka Auto GQL)

## This plugin is incomplete
On October 18th 2022, it will be ready for you to play with.

## Debug:
1. Run Burp using `java -jar -Xmx1g "/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar"`
2. Add `pdb.set_trace()` anywhere you want a breakpoint.
3. Go to Burp > Extender > Add and select burp-ext.py

## Prerequisites
1. Download Jython Standalone: https://www.jython.org/download.html
2. Open Burp > Extender > Options > Python Environment
3. Select the Jython jar

## Installation:
1. Open Burp > Extender > Extensions > Add
2. Extension Type: Python
3. Select file: burp-ext.py

## To Dos:
1. Separate into multiple files, and add build step to unify it back to one. (Burp requires that it be one file)
2. Add UI elements for adding URL, custom headers, and a "Go" button.
3. Search filter for queries.
5. Allow for user to manually alter injection points visually.
6. Allow for payload transformations (base64, etc.)

## Acknowledgements
1. The transformation on Introspection response, into requests comes from the wonderful inQL extension for Burp. For this reason I have included their Apache license. My plan is to eventually implement my own version of this. Not because it isn't awesome, or because I'm afraid of losing street cred, but because I have some specific needs that will eventually require me to rewrite it.
