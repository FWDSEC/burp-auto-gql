from burp import IBurpExtender
from burp import IScannerInsertionPointProvider
from urllib.parse import urlparse
import sys
import json
import re
from modules.gql_queries import generate

#DEBUG
import pdb
#END DEBUG

class BurpExtender(IBurpExtender, IScannerInsertionPointProvider):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # obtain an extension helpers object
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        #DEBUG
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()
        #END DEBUG
        
        # set our extension name
        callbacks.setExtensionName("Auto GraphQL Scanner")

        #DEBUG
        pdb.set_trace()
        #END DEBUG

        # TODO: Add UI element to get request headers from Burp user
        headers = [
            'sec-ch-ua: "Chromium";v="105", "Not)A;Brand";v="8"',
            'Accept: application/json',
            'Content-Type: application/json',
            'sec-ch-ua-mobile: ?0',
            'User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/105.0.5195.102 Safari/537.36',
            'sec-ch-ua-platform: "macOS"',
            'Sec-Fetch-Site: same-origin',
            'Sec-Fetch-Mode: cors',
            'Sec-Fetch-Dest: empty',
            'Accept-Encoding: gzip, deflate',
            'Accept-Language: en-US,en;q=0.9',
            'Cookie: language=en; welcomebanner_status=dismiss; cookieconsent_status=dismiss; continueCode=E3OzQenePWoj4zk293aRX8KbBNYEAo9GL5qO1ZDwp6JyVxgQMmrlv7npKLVy; env=graphiql:disable'
        ]

        # TODO: Add UI element to get this URL from Burp user
        url = 'http://localhost:5013/graphql'
        url_parts = urlparse( url )
        queries = self.fetch_queries( url, headers )

        for qtype in queries:
            for query in qtype:
                        
                request_bytes = self._helpers.buildHttpMessage(
                    headers,
                    self._helpers.stringToBytes( query )
                )
                """
                /**
                * This method can be used to send an HTTP request to the Burp Scanner tool
                * to perform an active vulnerability scan, based on a custom list of
                * insertion points that are to be scanned. If the request is not within the
                * current active scanning scope, the user will be asked if they wish to
                * proceed with the scan.
                *
                * @param host The hostname of the remote HTTP server.
                * @param port The port of the remote HTTP server.
                * @param useHttps Flags whether the protocol is HTTPS or HTTP.
                * @param request The full HTTP request.
                * @param insertionPointOffsets A list of index pairs representing the
                * positions of the insertion points that should be scanned. Each item in
                * the list must be an int[2] array containing the start and end offsets for
                * the insertion point.
                * @return The resulting scan queue item.
                */
                IScanQueueItem doActiveScan(
                        String host,
                        int port,
                        boolean useHttps,
                        byte[] request,
                        List<int[]> insertionPointOffsets);
                """
                callbacks.doActiveScan(
                        url_parts.hostname,
                        url_parts.port,
                        True,
                        request_bytes,
                        self.getInsertionPoints( request_bytes )
                    )
        
        # register ourselves as a scanner insertion point provider
        #callbacks.registerScannerInsertionPointProvider(self)

        return


    def fetch_queries( self, gql_endpoint, headers ):
        
        introspection_query =  "query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"
        url_parts = urlparse( gql_endpoint )
        
        """
        /**
        * This method builds an HTTP message containing the specified headers and
        * message body. If applicable, the Content-Length header will be added or
        * updated, based on the length of the body.
        *
        * @param headers A list of headers to include in the message.
        * @param body The body of the message, of <code>null</code> if the message
        * has an empty body.
        * @return The resulting full HTTP message.
        */
        """
        request_bytes = self._helpers.buildHttpMessage(
            headers,
            self._helpers.stringToBytes( f'{{"query":{introspection_query}}}' )
        )
        """
        /**
        * This method can be used to issue HTTP requests and retrieve their
        * responses.
        *
        * @param host The hostname of the remote HTTP server.
        * @param port The port of the remote HTTP server.
        * @param useHttps Flags whether the protocol is HTTPS or HTTP.
        * @param request The full HTTP request.
        * @return The full response retrieved from the remote server.
        */
        """
        response_bytes = self._callbacks.makeHttpRequest(
                url_parts.hostname,
                url_parts.port,
                True,
                request_bytes)
        
        gql_req = response_bytes.getRequest()
        gql_req_info = self._helpers.analyzeRequest(gql_req)
        body_offset = gql_req_info.getBodyOffset()
        introspection_result = self._helpers.bytesToString(gql_req)[body_offset:]
        queries = generate( json.loads( introspection_result ) )
        return queries

        
    # 
    # implement IScannerInsertionPointProvider
    #
    
    #def getInsertionPoints(self, baseRequestResponse):
    def getInsertionPoints( self, gql_req ):
 
        # retrieve the data parameter
        #gql_req = baseRequestResponse.getRequest()
        gql_req_info = self._helpers.analyzeRequest(gql_req)
        body_offset = gql_req_info.getBodyOffset()
        gql_body = self._helpers.bytesToString(gql_req)[body_offset:]
        
        if (gql_body is None):
            return None
        
        insertion_points = []
        
        gql_req_obj = json.loads( gql_body )

        pdb.set_trace()
        
        json_token_query = '"query":"'
        prefix_pad = body_offset + gql_body.find( json_token_query ) + len( json_token_query )
        for match in re.finditer( r'\(\s*[^$]\w+:\s*(\w+)\s*\)', gql_req_obj['query'] ):
            #insertion_points.append( self.create_insertion_point( match, gql_req, prefix_pad ) )
            insertion_points.append( [ prefix_pad + match.start(), prefix_pad + match.end() ] )

        if 'variables' in gql_req_obj.keys():
            json_token_query = '"variables":{'
            prefix_pad = body_offset + gql_body.find( json_token_query ) + len( json_token_query ) - 2 # 2 because of { used for the token and 
            #TODO replace regex with recursion through json object to find leaves, then find position of those leaves in the json string
            for match in re.finditer( r'":\s?"?([\w]+)"?[,}]', json.dumps( gql_req_obj['variables'] ) ):
                #insertion_points.append( self.create_insertion_point( match, gql_req, prefix_pad ) )
                insertion_points.append( [ prefix_pad + match.start(), prefix_pad + match.end() ] )

        pdb.set_trace()
        
        return insertion_points
        #return [ InsertionPoint(self._helpers, baseRequestResponse.getRequest(), gql_body) ]

    def create_insertion_point( self, re_match, base_request, prefix_pad = 0 ):

        pdb.set_trace()
        return self._helpers.makeScannerInsertionPoint(
                    "InsertionPointName",
                    base_request,
                    prefix_pad + re_match.start(),
                    prefix_pad + re_match.end() )

# 
# class implementing IScannerInsertionPoint
#
"""
class InsertionPoint(IScannerInsertionPoint):

    def __init__(self, helpers, baseRequest, gql_body):
        
        self._helpers = helpers
        self._baseRequest = baseRequest

        pdb.set_trace()
        # URL- and base64-decode the data
        gql_body_obj = json.loads( gql_body )
        
        if 'variables' in gql_body_obj.keys():
            # Add variables to insertion
            pass
        
        gql_query = gql_body['query']

        pdb.set_trace()

        # parse the location of the input string within the decoded data
        start = string.find(gql_body, "input=") + 6
        self._insertionPointPrefix = gql_body[:start]
        end = string.find(gql_body, "&", start)
        if (end == -1):
            end = gql_body.length()
        self._baseValue = gql_body[start:end]
        self._insertionPointSuffix = gql_body[end:]
        return
        
    # 
    # implement IScannerInsertionPoint
    #
    
    def getInsertionPointName(self):
        return "GraphQL input"

    def getBaseValue(self):
        return self._baseValue

    def buildRequest(self, payload):
        # build the raw data using the specified payload
        input = self._insertionPointPrefix + self._helpers.bytesToString(payload) + self._insertionPointSuffix;
        
        # Base64- and URL-encode the data
        input = self._helpers.urlEncode(self._helpers.base64Encode(input));
        
        # update the request with the new parameter value
        return self._helpers.updateParameter(self._baseRequest, self._helpers.buildParameter("data", input, IParameter.PARAM_BODY))

    def getPayloadOffsets(self, payload):
        # since the payload is being inserted into a serialized data structure, there aren't any offsets 
        # into the request where the payload literally appears
        return None

    def getInsertionPointType(self):
        return INS_EXTENSION_PROVIDED
            
"""