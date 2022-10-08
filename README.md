# Burp Plugin: Auto GraphQL Scanner (aka Auto GQL)

## This plugin is incomplete
On October 18th 2022, it will be ready for you to play with.

## Debug:
`java -jar -Xmx1g "/Applications/Burp Suite Professional.app/Contents/Resources/app/burpsuite_pro.jar"`

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
