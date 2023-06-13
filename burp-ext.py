from __future__ import absolute_import
import json

from jarray import array

from urlparse import urlparse


ORDER = {
    u"scalar": 0,
    u"enum": 1,
    u"type": 2,
    u"input": 3,
    u"interface": 4,
    u"union": 5
}
MINUS_INFINITE = -10000


def reverse_lookup_order(field, reverse_lookup):
    try:
        if field[u'required']:
            ret = 0
        else:
            ret = 10
        if field[u'array']:
            ret += 100
        if u'args' in field:
            ret += 1000
        ret += ORDER[reverse_lookup[field[u'type']]]
        return ret
    except KeyError:
        return 10000

def recurse_fields(schema, reverse_lookup, t, max_nest=7, non_required_levels=1, dinput=None,
                   params_replace=lambda schema, reverse_lookup, elem: elem, recursed=0):
    u"""
    Generates a JSON representation of the AST object representing a query

    :param schema:
        the output of a simplified schema

    :param reverse_lookup:
        a support hash that goes from typename to graphql type, useful to navigate the schema in O(1)

    :param t:
        type that you need to generate the AST for, since it is recursive it may be anything inside the graph

    :param max_nest:
        maximum number of recursive calls before returning the type name, this is needed in particularly broken cases
        where recurse_fields may not exit autonomously (EG. hackerone.com is using union to create sql or/and/not
        statements.) Consider that this will partially break params_replace calls.

    :param non_required_levels:
        expand up to non_required_levels levels automatically.

    :param dinput:
        the output object, it may even be provided from the outside.

    :param params_replace:
        a callback that takes (schema, reverse_lookup, elem) as parameter and returns a replacement for parameter.
        Needed in case you want to generate real parameters for queries.

    """
    if max_nest == 0:
        return params_replace(schema, reverse_lookup, t)
    if t not in reverse_lookup:
        return params_replace(schema, reverse_lookup, t)

    if dinput is None:
        dinput = {}

    if reverse_lookup[t] in [u'type', u'interface', u'input']:
        for inner_t, v in sorted(schema[reverse_lookup[t]][t].items(), key=lambda kv: reverse_lookup_order(kv[1], reverse_lookup)):
            if inner_t == u'__implements':
                for iface in v.keys():
                    interface_recurse_fields = recurse_fields(schema, reverse_lookup, iface, max_nest=max_nest,
                                                              non_required_levels=non_required_levels,
                                                              params_replace=params_replace)
                    dinput.update(interface_recurse_fields)
                continue
            # try to add at least one required inner, if you should not recurse anymore
            recurse = non_required_levels > 0 or (v[u'required'] and recursed <= 0) # required_only => v['required']
            if recurse:
                dinput[inner_t] = recurse_fields(schema, reverse_lookup, v[u'type'], max_nest=max_nest - 1,
                                                 non_required_levels=non_required_levels - 1,
                                                 params_replace=params_replace)
                recursed += 1
            if recurse and u'args' in v:
                if inner_t not in dinput or type(dinput[inner_t]) is not dict:
                    dinput[inner_t] = {}
                dinput[inner_t][u"args"] = {}
                for inner_a, inner_v in sorted(v[u'args'].items(), key=lambda kv: reverse_lookup_order(kv[1], reverse_lookup)):
                    # try to add at least a parameter, even if there are no required parameters
                    recurse_inner = non_required_levels > 0 or inner_v[u'required'] # required_only => v['required']
                    if recurse_inner:
                        arg = recurse_fields(schema, reverse_lookup, inner_v[u'type'], max_nest=max_nest-1, recursed=MINUS_INFINITE,
                                             non_required_levels=non_required_levels-1, params_replace=params_replace)
                        if u'array' in inner_v and inner_v[u'array']:
                            if type(arg) is dict:
                                arg = [arg]
                            else:
                                arg = u"[%s]" % arg
                        if u'required' in inner_v and inner_v[u'required']:
                            if type(arg) is not dict:
                                arg = u"!%s" % arg
                            else:
                                pass  # XXX: don't handle required array markers, this is a bug, but simplifies a lot the code
                        dinput[inner_t][u'args'][inner_a] = arg
                if len(dinput[inner_t][u"args"]) == 0:
                    del dinput[inner_t][u"args"]
                if len(dinput[inner_t]) == 0:
                    del dinput[inner_t]

        if len(dinput) == 0 and (t not in reverse_lookup or reverse_lookup[t] not in [u'enum', u'scalar']):
            items = list(schema[reverse_lookup[t]][t].items())
            if len(items) > 0:
                inner_t, v = items[0]
                dinput[inner_t] = recurse_fields(schema, reverse_lookup, v[u'type'], max_nest=max_nest - 1,
                                                non_required_levels=non_required_levels - 1, params_replace=params_replace)
    elif reverse_lookup[t] == u'union':
        # select the first type of the union
        for union in schema[u'union'][t].keys():
            dinput[u"... on %s" % union] = recurse_fields(schema, reverse_lookup, union, max_nest=max_nest,
                                                         non_required_levels=non_required_levels,
                                                         params_replace=params_replace)
    elif reverse_lookup[t] in [u'enum', u'scalar']:
        # return the type since it is an enum
        return params_replace(schema, reverse_lookup, t)
    return dinput


def dict_to_args(d):
    u"""
    Generates a string representing query arguments from an AST dict.

    :param d: AST dict
    """
    args = []
    for k, v in d.items():
        args.append(u"%s:%s" % (k, json.dumps(v).replace(u'"', u'').replace(u"u'", u"").replace(u"'", u"").replace(u'@', u'"')))
    if len(args) > 0:
        return u"(%s)" % u', '.join(args)
    else:
        return u""


def dict_to_qbody(d, prefix=u''):
    u"""
    Generates a string representing a query body from an AST dict.

    :param d: AST dict
    :param prefix: needed in case it will recurse
    """
    if type(d) is not dict:
        return u''
    s = u''
    iprefix = prefix + u'\t'
    args = u''
    for k, v in d.items():
        if k == u'args':
            args = dict_to_args(v)
        elif type(v) is dict:
            s += u'\n' + iprefix + k + dict_to_qbody(v, prefix=iprefix)
        else:
            s += u'\n' + iprefix + k
    if len(s) > 0:
        return u"%s {%s\n%s}" % (args, s, prefix)
    else:
        return args


def preplace(schema, reverse_lookup, t):
    u"""
    Replaces basic types and enums with default values.

    :param schema:
        the output of a simplified schema

    :param reverse_lookup:
        a support hash that goes from typename to graphql type, useful to navigate the schema in O(1)

    :param t:
        type that you need to generate the AST for, since it is recursive it may be anything inside the graph

    """
    if t == u'String':
        return u'@code*@'
    elif t == u'Int':
        return 1334
    elif t == u'Boolean':
        return u'true'
    elif t == u'Float':
        return 0.1334
    elif t == u'ID':
        return 14
    elif reverse_lookup[t] == u'enum':
        return list(schema[u'enum'][t].keys())[0]
    elif reverse_lookup[t] == u'scalar':
        # scalar may be any type, so the AST can be anything as well
        # since the logic is custom implemented I have no generic way of replacing them
        # for this reason we return it back as they are
        return t
    else:
        return t


def _recursive_name_get(obj):
    try:
        return obj[u'name'] or _recursive_name_get(obj[u'ofType'])
    except KeyError:
        return False


def _recursive_kind_of(obj, target):
    try:
        return obj[u'kind'] == target or _recursive_kind_of(obj[u'ofType'], target)
    except KeyError:
        return False
    except TypeError:
        return False


def simplify_introspection(data):
    u"""
    Generates a simplified introspection object based on an introspection query.
    This utility function is after used by many of the generators.

    # Parsing JSON response/file structure as follows
    # data
    #   __schema
    #       directives
    #       mutationType
    #       queryType
    #       subscriptionType
    #       types (kind, name, description)
    #              name (RootQuery, RootMutation, Subscriptions, [custom] OBJECT)
    #              fields
    #                     name (query names)
    #                     args
    #                            name (args names)
    #                            type
    #                                   name (args types)

    :type data: an introspection query dict
    """

    output = {}
    output[u'schema'] = {}
    schema = data[u'data'][u'__schema']

    # Get the Root query type
    if schema[u'queryType'] and u'name' in schema[u'queryType']:
        output[u'schema'][u'query'] = {
            u"type": schema[u'queryType'][u'name'],
            u"array": False,
            u"required": False
        }

    # Get the Root subscription type
    if schema[u'subscriptionType'] and u'name' in schema[u'subscriptionType']:
        output[u'schema'][u'subscription'] = {
            u"type": schema[u'subscriptionType'][u'name'],
            u"array": False,
            u"required": False
        }

    # Get the Root mutation type
    if schema[u'mutationType'] and u'name' in schema[u'mutationType']:
        output[u'schema'][u'mutation'] = {
            u"type": schema[u'mutationType'][u'name'],
            u"array": False,
            u"required": False
        }

    # Go over all the fields and simplify the JSON
    output[u'type'] = {}
    for type in schema[u'types']:
        if type[u'name'][0:2] == u'__': continue
        if type[u'kind'] == u'OBJECT':
            output[u'type'][type[u'name']] = {}
            if type[u'fields']:
                for field in type[u'fields']:
                    output[u'type'][type[u'name']][field[u'name']] = {
                        u"type": _recursive_name_get(field[u'type']),
                        u"required": field[u'type'][u'kind'] == u'NON_NULL',
                        u"array": _recursive_kind_of(field[u'type'], u'LIST'),
                    }
                    if field[u'args']:
                        output[u'type'][type[u'name']][field[u'name']][u"args"] = {}
                        for arg in field[u'args']:
                            output[u'type'][type[u'name']][field[u'name']][u'args'][arg[u'name']] = {
                                u"type": _recursive_name_get(arg[u'type']),
                                u"required": arg[u'type'][u'kind'] == u'NON_NULL',
                                u"array": _recursive_kind_of(arg[u'type'], u'LIST'),
                            }
                            if arg[u'defaultValue'] != None:
                                output[u'type'][type[u'name']][field[u'name']][u'args'][arg[u'name']][u'default'] = arg[
                                    u'defaultValue']
            if type[u'interfaces']:
                output[u'type'][type[u'name']][u'__implements'] = {}
                for iface in type[u'interfaces']:
                    output[u'type'][type[u'name']][u'__implements'][iface[u'name']] = {}

            if u'type' not in output[u'type'][type[u'name']] and u'args' in output[u'type'][type[u'name']]:
                output[u'type'][type[u'name']][u"type"] = output[u'type'][type[u'name']][u"args"][u"type"]


    # Get all the Enums
    output[u'enum'] = {}
    for type in schema[u'types']:
        if type[u'name'][0:2] == u'__': continue
        if type[u'kind'] == u'ENUM':
            output[u'enum'][type[u'name']] = {}
            for v in type[u'enumValues']:
                output[u'enum'][type[u'name']][v[u'name']] = {}

    # Get all the Scalars
    output[u'scalar'] = {}
    for type in schema[u'types']:
        if type[u'name'][0:2] == u'__': continue
        if type[u'kind'] == u'SCALAR' and type[u'name'] not in [u'String', u'Int', u'Float', u'Boolean', u'ID']:
            output[u'scalar'][type[u'name']] = {}

    # Get all the inputs
    output[u'input'] = {}
    for type in schema[u'types']:
        if type[u'name'][0:2] == u'__': continue
        if type[u'kind'] == u'INPUT_OBJECT':
            output[u'input'][type[u'name']] = {}
            if type[u'inputFields']:
                for field in type[u'inputFields']:
                    output[u'input'][type[u'name']][field[u'name']] = {
                        u"type": _recursive_name_get(field[u'type']),
                        u"required": field[u'type'][u'kind'] == u'NON_NULL',
                        u"array": _recursive_kind_of(field[u'type'], u'LIST'),
                    }

    # Get all the unions
    output[u'union'] = {}
    for type in schema[u'types']:
        if type[u'name'][0:2] == u'__': continue
        if type[u'kind'] == u'UNION':
            output[u'union'][type[u'name']] = {}
            for v in type[u'possibleTypes']:
                output[u'union'][type[u'name']][v[u'name']] = {}

    # Get all the interfaces
    output[u'interface'] = {}
    for type in schema[u'types']:
        if type[u'name'][0:2] == u'__': continue
        if type[u'kind'] == u'INTERFACE':
            output[u'interface'][type[u'name']] = {}
            if type[u'fields']:
                for field in type[u'fields']:
                    output[u'interface'][type[u'name']][field[u'name']] = {
                        u"type": _recursive_name_get(field[u'type']),
                        u"required": field[u'type'][u'kind'] == u'NON_NULL',
                        u"array": _recursive_kind_of(field[u'type'], u'LIST'),
                    }
                    if field[u'args']:
                        output[u'interface'][type[u'name']][field[u'name']][u"args"] = {}
                        for arg in field[u'args']:
                            output[u'interface'][type[u'name']][field[u'name']][u'args'][arg[u'name']] = {
                                u"type": _recursive_name_get(arg[u'type']),
                                u"required": arg[u'type'][u'kind'] == u'NON_NULL',
                                u"array": _recursive_kind_of(arg[u'type'], u'LIST'),
                            }
                            if arg[u'defaultValue'] != None:
                                output[u'interface'][type[u'name']][field[u'name']][u'args'][arg[u'name']][u'default'] = arg[
                                    u'defaultValue']
            if u'type' not in output[u'interface'][type[u'name']] and u'args' in output[u'interface'][type[u'name']]:
                output[u'interface'][type[u'name']][u"type"] = output[u'interface'][type[u'name']][u"args"][u"type"]

    return output


def generate(argument, detect=True):
    u"""
    Generate query templates

    :param argument: introspection query result
    :param qpath:
        directory template where to output the queries, first parameter is type of query and second is query name

    :param detect:
        retrieve placeholders according to arg type

    :param print:
        implements print in green

    :return: None
    """
    queries = {}

    s = simplify_introspection(argument)

    rev = {
        u"String": u'scalar',
        u"Int": u'scalar',
        u"Float": u'scalar',
        u"Boolean": u'scalar',
        u"ID": u'scalar',
    }
    for t, v in s.items():
        for k in v.keys():
            rev[k] = t

    for qtype, qvalues in s[u'schema'].items():
        if detect:
            rec = recurse_fields(s, rev, qvalues[u'type'], non_required_levels=2, params_replace=preplace)
        else:
            rec = recurse_fields(s, rev, qvalues[u'type'], non_required_levels=2)
        for qname, qval in rec.items():
            body = u"%s {\n\t%s%s\n}" % (qtype, qname, dict_to_qbody(qval, prefix=u'\t'))
            if detect:
                body = body.replace(u'!', u'')
            query = {u"query": body}
            if qtype not in queries.keys():
                queries[qtype] = {}
            queries[qtype][qname] = query

    return queries

from burp import IBurpExtender, ITab, IMessageEditorController
from java.util import ArrayList
from javax.swing import JTabbedPane, JSplitPane, JScrollPane, JFrame, JTable, JLabel, JTextField, JButton, JTextArea, JSeparator, JFileChooser
from javax.swing.filechooser import FileNameExtensionFilter
from java.awt.event import ActionListener
from javax.swing.table import AbstractTableModel, TableRowSorter
from java.lang import Boolean, String, Integer
from java.awt import Font
from urlparse import urlparse
#from java.awt.event import FocusListener
from urlparse import urlparse
import sys
import json
import re
from thread import start_new_thread
from copy import copy

#DEBUG
import pdb
#END DEBUG

class BurpExtender( IBurpExtender, ITab, AbstractTableModel, IMessageEditorController ):
    
    #
    # implement IBurpExtender
    #
    
    def	registerExtenderCallbacks(self, callbacks):
    
        # obtain an extension helpers object
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()

        # set our extension name
        callbacks.setExtensionName( u"Auto GraphQL Scanner" )

        #DEBUG
        sys.stdout = callbacks.getStdout()
        sys.stderr = callbacks.getStderr()
        #END DEBUG

        self.gqueries = ArrayList()
        
        self.gql_endpoint = u""
        self.gql_schema = u""

        self.headers = []
        self.headers_default = [
            u'Accept: application/json',
            u'Content-Type: application/json',
            u'User-Agent: Auto GQL via Burp',
            u'Accept-Encoding: gzip, deflate',
            u'Accept-Language: en-US,en;q=0.9',
            u'Connection: close'
        ]
        self.headers_custom = []
        self.headers_mandatory = [
            u'POST @@path@@ HTTP/1.1',
            u'Host: @@netloc@@',
            u'Origin: @@url@@'
        ]

        self.addUI()

        return


    # add file button to the UI
    class ButtonClickAction(ActionListener):
        def __init__(self, extender):
            self.extender = extender

    def actionPerformed(self, event):
        self.extender.load_json_schema()

    def load_json_schema(self, event=None):
        chooser = JFileChooser()
        jsonFilter = FileNameExtensionFilter("JSON files", ["json"])
        chooser.setFileFilter(jsonFilter)

        returnValue = chooser.showOpenDialog(None)
        if returnValue == JFileChooser.APPROVE_OPTION:
            selectedFile = chooser.getSelectedFile()
            file_path = selectedFile.getAbsolutePath()
            print("Selected file: ", file_path)  
            self.txt_input_gql_schema_file.setText(file_path)


    def addUI( self ):

        print( u"Loading UI..." )

        callbacks = self._callbacks

        # Main split pane
        self._splitpane_main = JSplitPane( JSplitPane.HORIZONTAL_SPLIT )

        # Top split pane with table and options
        self._splitpane_left = JSplitPane( JSplitPane.VERTICAL_SPLIT )
        self._splitpane_main.setLeftComponent( self._splitpane_left )
        
        # Queries Table - Top-Left
        gqueries_table = Table(self)
        # TODO: Disable until I fix the changeSelection to work with sorting
        #gqueries_table.setRowSorter( TableRowSorter(self) )
        scroll_pane = JScrollPane( gqueries_table )
        self._splitpane_left.setLeftComponent( scroll_pane )

        # Options - Top-Right
        frame = JFrame()
        opts_pane = frame.getContentPane()
        opts_pane.setLayout( None )

        opts_inner_y = 0

        label = JLabel("1.")
        y = 10
        h = 30
        opts_inner_y = y+h
        label.setBounds( 10, y, 30, h )
        opts_pane.add( label )
        
        hbar = JSeparator()
        hbar.setBounds( 40, y+h/2, 450, h )
        opts_pane.add( hbar )
        
        label = JLabel("GraphQL Endpoint URL:")
        y = opts_inner_y + 10
        h = 30
        opts_inner_y = y+h
        label.setBounds( 10, y, 150, h )
        opts_pane.add( label )
        
        placeholder_text = "http(s)://<host>/graphql"
        self.txt_input_gql_endpoint = JTextField( self.gql_endpoint if self.gql_endpoint != "" else placeholder_text )
        self.txt_input_gql_endpoint.setBounds( 190, y, 300, h )
        self.txt_input_gql_endpoint.setFont( Font( Font.MONOSPACED, Font.PLAIN, 14 ) )
        callbacks.customizeUiComponent( self.txt_input_gql_endpoint )
        opts_pane.add( self.txt_input_gql_endpoint )

        #  File Button
        btn_fetch_queries = JButton("Select file ...", actionPerformed=self.load_json_schema)
        y = opts_inner_y + 30
        h = 30
        opts_inner_y = y + h
        btn_fetch_queries.setBounds(10, y, 150, h)
        self._callbacks.customizeUiComponent(btn_fetch_queries)
        opts_pane.add(btn_fetch_queries)

        # File Text Field
        placeholder_schema_text = "Optionally provide introspection schema.json. URL still needs to be provied."
        self.txt_input_gql_schema_file = JTextField(self.gql_schema if self.gql_schema != "" else placeholder_schema_text)
        self.txt_input_gql_schema_file.setBounds(190, y, 720, h)
        self.txt_input_gql_schema_file.setFont(Font(Font.MONOSPACED, Font.PLAIN, 14))
        callbacks.customizeUiComponent(self.txt_input_gql_schema_file)
        opts_pane.add(self.txt_input_gql_schema_file)


        label = JLabel("Custom Request Headers:")
        y = opts_inner_y + 10
        h = 30
        opts_inner_y = y+h
        label.setBounds( 10, y, 150, h )
        opts_pane.add( label )
        
        self.txt_input_headers = JTextArea( self.get_headers_text(), 5, 30 )
        self.txt_input_headers.setWrapStyleWord(True)
        self.txt_input_headers.setLineWrap(True)
        scroll_txt_input_headers = JScrollPane( self.txt_input_headers )
        scroll_txt_input_headers.setVerticalScrollBarPolicy( JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED )
        y = opts_inner_y + 10
        h = 150
        opts_inner_y = y+h
        scroll_txt_input_headers.setBounds( 10, y, 470, h )
        callbacks.customizeUiComponent( self.txt_input_headers )
        callbacks.customizeUiComponent( scroll_txt_input_headers )
        opts_pane.add( scroll_txt_input_headers )

        label = JLabel("2.")
        y = opts_inner_y + 10
        h = 30
        opts_inner_y = y+h
        label.setBounds( 10, y, 30, h )
        opts_pane.add( label )
        
        hbar = JSeparator()
        hbar.setBounds( 40, y+h/2, 450, h )
        opts_pane.add( hbar )

        '''
        btn_fetch_queries = JButton( "Fetch Queries", actionPerformed=self._pull_queries )
        y = opts_inner_y + 10
        h = 30
        opts_inner_y = y+h
        btn_fetch_queries.setBounds( 10, y, 150, h )
        callbacks.customizeUiComponent( btn_fetch_queries )
        opts_pane.add( btn_fetch_queries )
        '''

        # New Button
        btn_fetch_queries = JButton( "Fetch Introspection ", actionPerformed=self._pull_queries )
        y = opts_inner_y + 10
        h = 30
        opts_inner_y = y+h
        btn_fetch_queries.setBounds( 10, y, 190, h )
        callbacks.customizeUiComponent( btn_fetch_queries )
        opts_pane.add( btn_fetch_queries )

        label = JLabel("3.")
        y = opts_inner_y + 10
        h = 30
        opts_inner_y = y+h
        label.setBounds( 10, y, 30, h )
        opts_pane.add( label )
        
        hbar = JSeparator()
        hbar.setBounds( 40, y+h/2, 450, h )
        opts_pane.add( hbar )
        
        btn_fetch_queries = JButton( "Run Scan", actionPerformed=self._scan_queries )
        y = opts_inner_y + 10
        h = 30
        opts_inner_y = y+h
        btn_fetch_queries.setBounds( 10, y, 150, h )
        callbacks.customizeUiComponent( btn_fetch_queries )
        opts_pane.add( btn_fetch_queries )
        
        self._splitpane_main.setRightComponent( opts_pane )

        # Request viewer - Bottom-Left
        tabs = JTabbedPane()
        self._requestViewer = callbacks.createMessageEditor( self, False )
        tabs.addTab( "Request", self._requestViewer.getComponent() )
        self._splitpane_left.setRightComponent( tabs )
        
        # customize our UI components
        callbacks.customizeUiComponent( self._splitpane_main )
        callbacks.customizeUiComponent( opts_pane )
        callbacks.customizeUiComponent( gqueries_table )
        callbacks.customizeUiComponent( scroll_pane )
        callbacks.customizeUiComponent( tabs )
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab( self )


    def get_headers_text( self ):

        if len( self.headers_custom ) == 0:
            self.headers_custom = copy( self.headers_default )

        return "\r\n".join( self.headers_custom )


    def draw_headers_text( self ):
        
        self.txt_input_headers.setText( self.get_headers_text() )
        

    def set_headers( self ):

        headers_custom_text = self.txt_input_headers.getText()
        self.headers_custom = re.split( r'\r?\n', headers_custom_text )
        
        re_token = r'@@([a-z]+)@@'
        url_parts = urlparse( self.gql_endpoint )
        replacements = {
            "path": url_parts.path,
            "netloc": url_parts.netloc,
            "url": self.gql_endpoint
        }

        replaced_headers = []
        for hdr in self.headers_mandatory:
            
            match = re.search( re_token, hdr )
            hdr = re.sub( re_token, replacements[ match.group(1) ], hdr )

            replaced_headers.append( hdr )

        self.headers = replaced_headers + self.headers_custom


    def _pull_queries( self, event ):

        # TODO: (1) Validate URL
        #       (2) Provide visual feedback that introspection is in progress
        self.gql_endpoint = self.txt_input_gql_endpoint.getText()
        self.set_headers()
        self.draw_headers_text()
        start_new_thread( self.pull_queries, (1,) )
    
    def pull_queries( self, not_used ):
        try:
            self.introspection_to_queries( self.introspect() )
        except Exception as e:
            print("An unexpected error occurred: verify if you entered the correct GraphQL Endpoint URL")
            print("Details:", e)
            return

    
    #
    # implement ITab
    #
    
    def getTabCaption(self):
        return "Auto GQL"
    
    def getUiComponent(self):
        return self._splitpane_main


    #
    # extend AbstractTableModel
    #

    def getColumnHeaders( self ):
        return [
            "[   ]",
            "#",
            "Query Type",
            "Request Name",
            "Insertion Points",
        ]
    
    def getRowCount(self):
        try:
            return self.gqueries.size()
        except:
            return 0

    def getColumnCount(self):
        return len( self.getColumnHeaders() )

    def getColumnName(self, column_index):
        cols = self.getColumnHeaders()

        if column_index < len(cols):
            return cols[ column_index ]

        return ""
   
    def getColumnClass( self, column_index ):
        
        if column_index == 0:
            return Boolean
        if column_index == 1 or column_index == 4:
            return Integer

        return String

    def getValueAt(self, row_index, column_index):
        gquery = self.gqueries.get( row_index )

        cols = [
            gquery['enabled'], # Checkbox
            row_index + 1, # Row number
            gquery[ 'type' ], #Query Type (Query, Mutation, or Subscription)
            gquery['name'], # Query Name
            len( gquery['insertion_points'] ) # Number of Insertion Points
        ]

        if column_index < len(cols):
            return cols[ column_index ]
        
        return ""

    
    #
    # Custom Methods
    #

    def _scan_queries( self, event ):

        # TODO: (1) Gray out button with info tooltip saying to fetch queries first
        #       (2) Provide feedback that the scan has started
        if self.gqueries.size() > 0:
            start_new_thread( self.scan_queries, (1,) )

    def scan_queries( self, not_used ):

        url_parts = urlparse( self.gql_endpoint )

        for gquery in self.gqueries:

            if gquery['enabled'] == False:
                continue

            #callbacks.sendToIntruder( # Used to debug Insertion Points visually
            self._callbacks.doActiveScan(
                url_parts.hostname,
                self.web_port( self.gql_endpoint ),
                url_parts.scheme == 'https',
                gquery['query'],
                gquery['insertion_points']
            )


    def introspect(self):
        try:
            # Try to parse the URL
            url_parts = urlparse(self.gql_endpoint) 

            hostname = url_parts.hostname
            scheme = url_parts.scheme
            port = url_parts.port if url_parts.port else (443 if scheme == 'https' else 80)

            # Check if the URL has valid protocol
            if scheme not in ['http', 'https']:
                raise ValueError("Invalid protocol in URL: {}".format(scheme))

            introspection_query =  u"query IntrospectionQuery{__schema{queryType{name}mutationType{name}subscriptionType{name}types{...FullType}directives{name description locations args{...InputValue}}}}fragment FullType on __Type{kind name description fields(includeDeprecated:true){name description args{...InputValue}type{...TypeRef}isDeprecated deprecationReason}inputFields{...InputValue}interfaces{...TypeRef}enumValues(includeDeprecated:true){name description isDeprecated deprecationReason}possibleTypes{...TypeRef}}fragment InputValue on __InputValue{name description type{...TypeRef}defaultValue}fragment TypeRef on __Type{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name ofType{kind name}}}}}}}}"

            request_bytes = self._helpers.buildHttpMessage(
                self.headers,
                self._helpers.stringToBytes( '{"query":"' + introspection_query + '"}' )
            )

            http_service = self._helpers.buildHttpService(
                hostname,
                port,
                scheme
            )

            print("Sending Introspection Query")

            intros_res = self._callbacks.makeHttpRequest(
                    http_service,
                    request_bytes
                )
            
            gql_res = intros_res.getResponse()
            gql_res_info = self._helpers.analyzeResponse( gql_res )
            body_offset = gql_res_info.getBodyOffset()
            introspection_result = self._helpers.bytesToString( gql_res )[body_offset:]

            return introspection_result

        except ValueError as ve:
            print("An error occurred during URL parsing: {}".format(ve))
        except Exception as e:
            print("An unexpected error occurred:")
            print("Details:", e)
            return


    def introspection_to_queries( self, introspection_result ):
        # Load introspection result
        introspection_data = None
        # Try getting introspection results from URL, if fails attempt to read a local schema.json
        try:
            introspection_data = json.loads(introspection_result)
        except ValueError:
            print(u"Failed to read JSON from URL, trying to read from local file.")
            try:
                with open(self.txt_input_gql_schema_file.getText(), 'r') as file: 
                    introspection_data = json.load(file)
            except (IOError, ValueError):
                print(u"Failed to read JSON from local file. Cannot proceed.")
                return


        queries = generate(introspection_data)

        row_count = self.getRowCount()
        if row_count > 0:
            self.fireTableRowsDeleted( 0, row_count - 1 )
            self.gqueries.clear()

        for qtype_nm, qtype in queries.items():
            for qname,query in qtype.items():

                query_s = json.dumps( query )

                # Skip endpoints that remove data
                # TODO: Move to UI
                # if any(substring in query_s.lower() for substring in ['delete','remove','clear']):
                #     continue
                            
                request_bytes = self._helpers.buildHttpMessage(
                    self.headers,
                    self._helpers.stringToBytes( query_s )
                )

                insertion_points = self.getInsertionPoints( request_bytes )

                self.gqueries.add( {
                    "type": qtype_nm,
                    "name": qname,
                    "query": request_bytes,
                    "insertion_points": insertion_points,
                    "enabled": len( insertion_points ) > 0
                } )

                # Update table view
                row = self.gqueries.size() - 1
                self.fireTableRowsInserted(row, row)

        return self.gqueries
        

    def getInsertionPoints( self, gql_req ):
 
        # retrieve the data parameter
        gql_req_info = self._helpers.analyzeRequest(gql_req)
        body_offset = gql_req_info.getBodyOffset()
        gql_body = self._helpers.bytesToString(gql_req)[body_offset:]
        
        if (gql_body is None):
            return None
        
        insertion_points = []
        
        gql_req_obj = json.loads( gql_body )
        
        json_token_query = u'"query": "'
        prefix_pad = body_offset + gql_body.find( json_token_query ) + len( json_token_query )
        # The query appears with escape slashes in the HTTP request, but not in the deserialized object. Add them back in.
        query_w_slashes = re.sub( ur'([\n\t\r"])', ur'\\\1', gql_req_obj['query'] )
        # TODO: Support all data types. Setting payload data types for Active Scanner is a necessity but doesn't seem to be an API option.
        # Phase 2 of this TODO is adding support for custom scalars
        #regex_all_data_types = ur'[^$]\w+:\s*[\\"]*([\w*]+)[\\"]*\s*[,)]'
        regex_strings_only = ur'(code\*)'
        for match in re.finditer( regex_strings_only, query_w_slashes ):
            insertion_points.append( array([ prefix_pad + match.start(1), prefix_pad + match.end(1) ], 'i') )

        if u'variables' in gql_req_obj.keys():
            json_token_query = u'"variables":{'
            prefix_pad = body_offset + gql_body.find( json_token_query ) + len( json_token_query ) - 2 # 2 because of { used for the token and 
            #TODO replace regex with recursion through json object to find leaves, then find position of those leaves in the json string
            for match in re.finditer( regex_strings_only, json.dumps( gql_req_obj[u'variables'] ) ):
                insertion_points.append( array([ prefix_pad + match.start(1), prefix_pad + match.end(1) ], 'i') )
        
        return insertion_points

    def create_insertion_point( self, re_match, base_request, prefix_pad = 0 ):

        return self._helpers.makeScannerInsertionPoint(
                    u"InsertionPointName",
                    base_request,
                    prefix_pad + re_match.start(),
                    prefix_pad + re_match.end() )

    def web_port( self, url ):

        url_parts = urlparse( url )

        if url_parts.port:
            return url_parts.port

        return 443 if url_parts.scheme.lower() == 'https' else 80

#
# extend JTable to handle cell selection
#
class Table( JTable ):
    def __init__(self, extender):
        self._extender = extender
        self.setModel(extender)
    
    def changeSelection(self, row, col, toggle, extend):

        gquery = self._extender.gqueries.get( row )

        if col == 0:

            gquery['enabled'] = not gquery['enabled']
            self._extender.gqueries.set( row, gquery )
            self._extender.fireTableRowsUpdated( row, row )
            return
    
        # Show the GQL Query for the selected row
        self._extender._requestViewer.setMessage( self._extender._helpers.bytesToString( gquery['query'] ), True )
        
        JTable.changeSelection(self, row, col, toggle, extend)
