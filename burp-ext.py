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


default_req_param_vals = {
    u'String': u'"$string$"',
    u'Int': 1334,
    u'Boolean': u'true',
    u'Float': 0.1334,
    u'ID': 14
}

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

    if t in default_req_param_vals:
        type_default = default_req_param_vals[ t ]
        if type(type_default) == unicode:
            type_default = type_default.replace( '"', '@' )
        return type_default
    if reverse_lookup[t] == u'enum':
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
from javax.swing import JPanel, JTabbedPane, JSplitPane, JScrollPane, JTable, JLabel, JTextField, JButton, JTextArea, JSeparator, JFileChooser, JComboBox, Timer
from javax.swing.filechooser import FileNameExtensionFilter
from javax.swing.event import DocumentListener
from java.awt import Color, GridBagLayout, GridBagConstraints, Insets, BorderLayout
from javax.swing.border import EmptyBorder, LineBorder
from javax.swing.table import AbstractTableModel
from java.lang import Boolean, String, Integer
from java.awt import Font, Dimension
from urlparse import urlparse
import json
import re
from thread import start_new_thread
from copy import copy
from uuid import uuid4
import sys

#DEBUG
#import pdb
#END DEBUG

SAVESTATE_PREFIX = u"AutoGQL_savestate_"

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
        # sys.stdout = callbacks.getStdout()
        # sys.stderr = callbacks.getStderr()
        #END DEBUG

        saved_gqueries = callbacks.loadExtensionSetting( SAVESTATE_PREFIX+"gqueries" )
        self.gqueries = ArrayList( json.loads( saved_gqueries ) ) if saved_gqueries else ArrayList()
        
        self.gql_endpoint = callbacks.loadExtensionSetting( SAVESTATE_PREFIX+"gql_endpoint" ) or u""
        self.gql_schema = callbacks.loadExtensionSetting( SAVESTATE_PREFIX+"gql_schema" ) or u""

        self.headers = []
        self.headers_default = [
            u'Origin: @@url@@',
            u'Accept: application/json',
            u'Content-Type: application/json',
            u'User-Agent: Auto GQL via Burp',
            u'Accept-Encoding: gzip, deflate',
            u'Accept-Language: en-US,en;q=0.9',
            u'Connection: close'
        ]
        self.headers_mandatory = [
            u'POST @@path@@ HTTP/1.1',
            u'Host: @@netloc@@'
        ]
        saved_headers = callbacks.loadExtensionSetting( SAVESTATE_PREFIX+"headers_custom" )
        self.headers_custom = json.loads( saved_headers ) if saved_headers else []
        
        self.in_prop_names = []

        self.add_ui()

        return


    # add file button to the UI
    def load_json_schema_file(self, event=None):
        chooser = JFileChooser()
        json_filter = FileNameExtensionFilter("JSON files", ["json","graphql"])
        chooser.setFileFilter(json_filter)

        dialog_selection = chooser.showOpenDialog(None)
        if dialog_selection == JFileChooser.APPROVE_OPTION:
            schema_file = chooser.getSelectedFile()
            file_path = schema_file.getAbsolutePath()
            self.txt_input_gql_schema_file.setText(file_path)

    
    def create_locked_req_props_ui( self, event ):

        callbacks = self._callbacks

        self.grid_constraints.gridy = len( self.locked_req_props_elements.keys() ) + 1

        self.grid_constraints.gridx = 0
        opts_input_locked_property = JComboBox( self.in_prop_names )
        opts_input_locked_property.setFont( Font( Font.MONOSPACED, Font.PLAIN, 14 ) )
        callbacks.customizeUiComponent( opts_input_locked_property )
        self.locked_prop_tabs_panel.add( opts_input_locked_property, self.grid_constraints )

        self.grid_constraints.gridx = 1
        txt_input_locked_property_value = JTextField( 50 )
        txt_input_locked_property_value.setFont( Font( Font.MONOSPACED, Font.PLAIN, 14 ) )
        callbacks.customizeUiComponent( txt_input_locked_property_value )
        self.locked_prop_tabs_panel.add( txt_input_locked_property_value, self.grid_constraints )

        self.grid_constraints.gridx = 2
        rnd_index = uuid4().hex
        btn_add_locked_prop_fields = JButton( 'Remove', actionPerformed=lambda event: self.locked_prop_remove_and_reset_default( event, rnd_index ) )
        callbacks.customizeUiComponent( btn_add_locked_prop_fields )
        self.locked_prop_tabs_panel.add( btn_add_locked_prop_fields, self.grid_constraints )

        # Required for dynamically adding components without explicitly repainting
        self.locked_prop_tabs_panel.revalidate()

        self.locked_req_props_elements[ rnd_index ] = ( opts_input_locked_property, txt_input_locked_property_value )


    def locked_prop_remove_and_reset_default( self, event, index ):
        
        btn_del = event.getSource()
        parent_panel = btn_del.getParent()
        prop_el, val_el = self.locked_req_props_elements[ index ]

        parent_panel.remove(btn_del)
        parent_panel.remove(prop_el)
        parent_panel.remove(val_el)

        parent_panel.revalidate()

        del self.locked_req_props_elements[ index ]

    
    def add_ui( self ):

        print( u"Loading UI..." )

        callbacks = self._callbacks


        # Queries Table / Requests (Left half of main)
        self._splitpane_left = JSplitPane( JSplitPane.VERTICAL_SPLIT )
        # Input / Advanced Options (Right half of main)
        self._right_panel = JPanel()
        self._right_panel.setLayout( BorderLayout() )
        # Main split pane
        self._splitpane_main = JSplitPane( JSplitPane.HORIZONTAL_SPLIT, self._splitpane_left, self._right_panel )
        
        # Queries Table - Left-Top
        gqueries_table = QueriesTable(self)
        # TODO: Disabled sorting until I fix the changeSelection to work with sorting
        #gqueries_table.setRowSorter( TableRowSorter(self) )
        scroll_pane = JScrollPane( gqueries_table )
        self._splitpane_left.setLeftComponent( scroll_pane )

        # Request viewer - Left-Bottom
        tabs = JTabbedPane()
        editable = False
        self._requestViewer = callbacks.createMessageEditor( self, editable )
        tabs.addTab( "Request", self._requestViewer.getComponent() )
        self._splitpane_left.setRightComponent( tabs )

        # Options - Right-Top
        opts_tabs = JTabbedPane()
        opts_pane = JPanel()
        opts_pane.setLayout( None )

        # TAB - "Start"
        # Row 1 (GraphQL Endpoint URL)
        ## Number and Separator
        opts_inner_y = 0
        y = opts_inner_y + 30
        h = 30
        

        label = JLabel("1.")
        label.setBounds( 10, y, 30, h )
        opts_pane.add( label )
        
        hbar = JSeparator()
        hbar.setBounds( 40, y+h/2, 450, h )
        opts_pane.add( hbar )
        opts_inner_y = y + h
        
        ## Label and Input
        y = opts_inner_y + 30
        opts_inner_y = y + h
        label = JLabel("GraphQL Endpoint URL:")
        label.setBounds( 40, y, 150, h )
        opts_pane.add( label )
        
        self.placeholder_endpoint_text = "http(s)://<host>/graphql"
        self.txt_input_gql_endpoint = JTextField( self.gql_endpoint if self.gql_endpoint != "" else self.placeholder_endpoint_text )
        x = 230
        w = 400
        self.txt_input_gql_endpoint.setBounds( 1, 1, w, h )
        self.txt_input_gql_endpoint.setFont( Font( Font.MONOSPACED, Font.PLAIN, 14 ) )
        callbacks.customizeUiComponent( self.txt_input_gql_endpoint )
        label_wrap = JPanel()
        label_wrap.setLayout( None )
        label_wrap.setBorder( None )
        label_wrap.setBounds( x, y, w+2, h+2 )
        label_wrap.add( self.txt_input_gql_endpoint )
        input_savestate_listener = TextFieldSaveStateListener( callbacks, self.txt_input_gql_endpoint, "gql_endpoint" )
        self.txt_input_gql_endpoint.getDocument().addDocumentListener( input_savestate_listener )
        input_validation_listener = TextFieldValidationListener( self.txt_input_gql_endpoint, uri_validator, self.placeholder_endpoint_text )
        self.txt_input_gql_endpoint.getDocument().addDocumentListener( input_validation_listener )
        opts_pane.add( label_wrap )

        # Row 2 (GraphQL Schema File)
        ##  Load File Button
        btn_select_schema_file = JButton( "Select file ...", actionPerformed=self.load_json_schema_file )
        y = opts_inner_y + 30
        h = 30
        opts_inner_y = y + h
        btn_select_schema_file.setBounds( 40, y, 150, h )
        self._callbacks.customizeUiComponent( btn_select_schema_file )
        opts_pane.add( btn_select_schema_file )

        ## File Text Field
        self.placeholder_schema_text = "Optionally provide introspection schema.json. URL still needs to be provied."
        self.txt_input_gql_schema_file = JTextField( self.gql_schema if self.gql_schema != "" else self.placeholder_schema_text )
        self.txt_input_gql_schema_file.setBounds( 230, y, 400, h )
        self.txt_input_gql_schema_file.setFont( Font( Font.MONOSPACED, Font.PLAIN, 14 ) )
        callbacks.customizeUiComponent( self.txt_input_gql_schema_file )
        opts_pane.add( self.txt_input_gql_schema_file )

        # Row 3 (Custom Request Headers)
        ## Label, input, and help text
        label = JLabel("Custom Request Headers:")
        y = opts_inner_y + 10
        h = 30
        opts_inner_y = y+h
        label.setBounds( 40, y, 150, h )
        opts_pane.add( label )
        
        self.txt_input_headers = JTextArea( self.get_headers_text(), 5, 30 )
        self.txt_input_headers.setWrapStyleWord( True )
        self.txt_input_headers.setLineWrap( True )
        scroll_txt_input_headers = JScrollPane( self.txt_input_headers )
        scroll_txt_input_headers.setVerticalScrollBarPolicy( JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED )
        y = opts_inner_y + 10
        h = 150
        opts_inner_y = y+h
        scroll_txt_input_headers.setBounds( 40, y, 470, h )
        callbacks.customizeUiComponent( self.txt_input_headers )
        callbacks.customizeUiComponent( scroll_txt_input_headers )
        opts_pane.add( scroll_txt_input_headers )
        
        label = JLabel("<html>\
                            <p>Header Variables:</p>\
                            <ul>\
                                <li><b>@@url@@</b> => The target GraphQL Endpoint URL.</li>\
                                <li><b>@@netloc@@</b> => The network location of the GraphQL Endpoint URL. Everything between \"http(s)://\" and the path.</li>\
                                <li><b>@@path@@</b> => The path portion of the GraphQL Endpoint URL.</li>\
                            </ul>\
                        </html>")
        label.putClientProperty( "html.disable", None )
        y = opts_inner_y + 10
        h = 100
        opts_inner_y = y+h
        label.setBounds( 40, y, 470, h )
        opts_pane.add( label )

        # Row 4 (Fetch Introspection Button)
        ## Number and Line
        label = JLabel("2.")
        y = opts_inner_y + 10
        h = 30
        opts_inner_y = y+h
        label.setBounds( 10, y, 30, h )
        opts_pane.add( label )
        
        hbar = JSeparator()
        hbar.setBounds( 40, y+h/2, 450, h )
        opts_pane.add( hbar )

        ## Fetch Introspection Button 
        btn_fetch_queries = JButton( "Get All Possible Queries", actionPerformed=self._pull_queries )
        y = opts_inner_y + 10
        h = 30
        opts_inner_y = y+h
        btn_fetch_queries.setBounds( 40, y, 190, h )
        callbacks.customizeUiComponent( btn_fetch_queries )
        opts_pane.add( btn_fetch_queries )

        # Row 5 (Run Scan Button)
        ## Number and Line
        label = JLabel("3.")
        y = opts_inner_y + 10
        h = 30
        opts_inner_y = y+h
        label.setBounds( 10, y, 30, h )
        opts_pane.add( label )
        
        hbar = JSeparator()
        hbar.setBounds( 40, y+h/2, 450, h )
        opts_pane.add( hbar )
        
        ## Run Scan button
        btn_fetch_queries = JButton( "Send to Active Scanner", actionPerformed=self._scan_queries )
        y = opts_inner_y + 10
        h = 30
        opts_inner_y = y+h
        btn_fetch_queries.setBounds( 40, y, 150, h )
        callbacks.customizeUiComponent( btn_fetch_queries )
        opts_pane.add( btn_fetch_queries )

        # TAB - "Locked Properties"
        self.locked_prop_tabs_panel = JPanel()
        self.locked_prop_tabs_panel.setLayout( GridBagLayout() )
        self.grid_constraints = GridBagConstraints()
        self.grid_constraints.fill = GridBagConstraints.HORIZONTAL
        self.grid_constraints.insets = Insets(5, 5, 5, 5)
        self.grid_constraints.anchor = GridBagConstraints.NORTHWEST
        self.locked_prop_tabs_panel.setMaximumSize( Dimension( 700, 200 ) )

        self.grid_constraints.gridy = 0
        
        self.grid_constraints.gridx = 0
        label = JLabel("Query Property Name")
        self.locked_prop_tabs_panel.add( label, self.grid_constraints )

        self.grid_constraints.gridx = 1
        label = JLabel("Locked Value")
        self.locked_prop_tabs_panel.add( label, self.grid_constraints )

        self.grid_constraints.gridx = 2
        btn_add_locked_prop_fields = JButton( 'Add New', actionPerformed=self.create_locked_req_props_ui )
        callbacks.customizeUiComponent( btn_add_locked_prop_fields )
        self.locked_prop_tabs_panel.add( btn_add_locked_prop_fields, self.grid_constraints )

        self.locked_req_props_elements = {}
        self.locked_req_props = {}

        container_pnl = JPanel()
        container_pnl.setLayout( GridBagLayout() )
        container_pnl.setBorder( EmptyBorder(20, 20, 20, 20) )
        container_constraints = GridBagConstraints()
        container_constraints.gridx = 0
        container_constraints.gridy = 0
        container_constraints.weightx = 1
        container_constraints.weighty = 1
        container_constraints.anchor = GridBagConstraints.NORTHWEST
        container_pnl.add( self.locked_prop_tabs_panel, container_constraints )
        scroll_locked_prop_tabs_panel = JScrollPane( container_pnl )
        scroll_locked_prop_tabs_panel.setVerticalScrollBarPolicy( JScrollPane.VERTICAL_SCROLLBAR_AS_NEEDED )
        callbacks.customizeUiComponent( scroll_locked_prop_tabs_panel )
        
        opts_tabs.addTab( "Start", opts_pane )
        opts_tabs.addTab( "Locked Properties", scroll_locked_prop_tabs_panel )
        self._right_panel.add( opts_tabs )
        
        # customize our UI components
        callbacks.customizeUiComponent( self._splitpane_main )
        callbacks.customizeUiComponent( opts_pane )
        callbacks.customizeUiComponent( opts_tabs )
        callbacks.customizeUiComponent( gqueries_table )
        callbacks.customizeUiComponent( scroll_pane )
        callbacks.customizeUiComponent( tabs )
        
        # add the custom tab to Burp's UI
        callbacks.addSuiteTab( self )


    def update_locked_props_comboboxes( self, introspection_data ):

        in_prop_names = self.get_input_names( introspection_data )
        if in_prop_names == self.in_prop_names:
            return
        
        self.in_prop_names = in_prop_names

        for prop_box, val_box in self.locked_req_props_elements.values():
            prop_box.removeAllItems()

            for prop_nm in self.in_prop_names:
                prop_box.addItem( prop_nm )

    
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
        for hdr in self.headers_mandatory + self.headers_custom:
            
            match = re.search( re_token, hdr )
            if match:
                hdr = re.sub( re_token, replacements[ match.group(1) ], hdr )

            replaced_headers.append( hdr )

        self.headers = replaced_headers


    def _pull_queries( self, event ):

        # TODO: (1) Provide visual feedback that introspection is in progress
        gql_endpoint_input = self.txt_input_gql_endpoint.getText()

        if not uri_validator( gql_endpoint_input ):
            # Show error
            return
        
        self.gql_endpoint = gql_endpoint_input
        self.set_headers()
        self.draw_headers_text()
        start_new_thread( self.pull_queries, (1,) )
    
    def pull_queries( self, not_used ):
        
        introspection_data = None

        # Try getting introspection results from URL, if fails attempt to read a local schema.json
        try:
            introspection_data = json.loads( self.introspect() )
        except ValueError:
            print(u"Bad response from server. Check the URL if you're sure that the server has Introspection enabled. Otherwise load the schema file.")

        self.update_locked_props_comboboxes( introspection_data )
        
        try:
            self.introspection_to_queries( introspection_data )
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

        # TODO: (1) Provide feedback that the scan has started

        if self.gql_endpoint.strip() == '' or self.gql_endpoint == self.placeholder_endpoint_text:
            err = u"URL is required for running the scan."
            print( err )
            return

        if self.gqueries.size() > 0:
            start_new_thread( self.scan_queries, (1,) )

    def scan_queries( self, not_used ):

        url_parts = urlparse( self.gql_endpoint )

        for gquery in self.gqueries:

            if gquery['enabled'] == False:
                continue

            # Filled locked properties
            gquery_s = gquery['query_s']
            for prop_el,val_el in self.locked_req_props_elements.values():

                prop = prop_el.getSelectedItem()
                lp_qname = prop[:prop.find(":")]
                lp_qparam = prop[prop.find(":")+2:]
                
                if lp_qname == gquery['name']:
                    gquery_s = self.set_gquery_req_param( gquery_s, lp_qparam, val_el.getText() )
                    
            # Set custom headers, and reset insertion points if locked req props are defined
            gquery = self.create_gquery( gquery_s, gquery['type'], gquery['name'] )

            #callbacks.sendToIntruder( # Used to debug Insertion Points visually
            scan_queue_item = self._callbacks.doActiveScan(
                url_parts.hostname,
                self.web_port( self.gql_endpoint ),
                url_parts.scheme == 'https',
                gquery['query'],
                gquery['insertion_points']
            )

            status = scan_queue_item.getStatus()
            # TODO: Display scan status


    def set_gquery_req_param( self, gquery_json, lp_qparam, lp_value ):

        gquery_s = json.loads( gquery_json )['query']

        default_values_rgx_str = "|".join( re.escape( str( v ) ) for v in default_req_param_vals.values() )

        regex_locked_prop = ur'(\W'+re.escape(lp_qparam)+':\s*)('+default_values_rgx_str+')'
        param_default = re.search( regex_locked_prop, gquery_s ).group(2)
        
        if param_default == default_req_param_vals['String']:

            lp_value = '"'+lp_value+'"'
        
        gquery_s = re.sub( regex_locked_prop, ur'\g<1>'+lp_value, gquery_s, count=1 )

        return json.dumps( { "query": gquery_s } )
    
    
    def introspect(self):

        schema_file_text = self.txt_input_gql_schema_file.getText()
        if schema_file_text.strip() != '' and schema_file_text != self.placeholder_schema_text:
            try:
                with open( self.txt_input_gql_schema_file.getText(), 'r' ) as file:
                    return file.read()
            except ( IOError, ValueError ):
                print( u"Failed to read schema from local file. Trying Introspection query." )
            
        if self.gql_endpoint.strip() == '' or self.gql_endpoint == self.placeholder_endpoint_text:
            err = u"URL is required for fetching introspection."
            print( err )
            raise ValueError( err )
        
        try:
            # Try to parse the URL
            url_parts = urlparse(self.gql_endpoint) 

            hostname = url_parts.hostname
            scheme = url_parts.scheme
            port = url_parts.port if url_parts.port else ( 443 if scheme == 'https' else 80 )

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


    def introspection_to_queries( self, introspection_data ):
        
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
                            
                gquery = self.create_gquery( query_s, qtype_nm, qname )
                self.gqueries.add( gquery )

                # Update table view
                row = self.gqueries.size() - 1
                self.fireTableRowsInserted(row, row)

        return self.gqueries
    

    def create_gquery( self, query_s, qtype_nm, qname ):

        request_bytes = self._helpers.buildHttpMessage(
            self.headers,
            self._helpers.stringToBytes( query_s )
        )

        insertion_points = self.get_insertion_points( request_bytes )

        return {
            "type": qtype_nm,
            "name": qname,
            "query": request_bytes,
            "insertion_points": insertion_points,
            "enabled": len( insertion_points ) > 0,
            "query_s": query_s
        }
        

    def get_input_names( self, introspection_data ):

        in_prop_names = []
        s_introspection_data = simplify_introspection(introspection_data)

        for qparent in s_introspection_data['type'].values():
            for qname, qdata in qparent.items():
                
                if "args" not in qdata:
                    continue

                for qarg_nm in qdata['args'].keys():
                    in_prop_names.append( qname+": "+qarg_nm )

        # Dedupe and sort
        in_prop_names = list( set( in_prop_names ) )
        in_prop_names.sort()
        
        return in_prop_names

    
    def get_insertion_points( self, gql_req ):
 
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
        regex_strings_only = ur'(\$\w+\$)'
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
    
# Global Helpers

def uri_validator( urlstr ):
    try:
        result = urlparse( urlstr )
        return all([result.scheme, result.netloc])
    except:
        return False

#
# extend JTable to handle cell selection
#
class QueriesTable( JTable ):
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
        is_request = True
        self._extender._requestViewer.setMessage( self._extender._helpers.bytesToString( gquery['query'] ), is_request )
        
        JTable.changeSelection(self, row, col, toggle, extend)

#
# Extend DocumentListner input validation
#
class TextFieldValidationListener( DocumentListener ):
    
    def __init__( self, text_component, validator_fn, placeholder_text='' ):
        self.text_component = text_component
        self.placeholder_text = placeholder_text
        self.validator_fn = validator_fn
        self.url_pnl = text_component.getParent()
        self.timer = Timer(10, self._fade_border)  # Timer with 10ms delay
        self.timer.setRepeats(False)
        self.current_alpha = 0  # Start with an invisible border

    def insertUpdate( self, event ):
        self._text_updated( event )

    def removeUpdate( self, event ):
        self._text_updated( event )

    def _text_updated( self, event ):
        url = self.text_component.getText()
        self.target_color = Color.green if self.validator_fn( url ) else Color.red
        self.url_pnl.setBorder( LineBorder( self.target_color, 1 ) )
        self.current_alpha = 255
        self.timer.restart()  # Restart the timer on every update

    def _fade_border(self, event):
        alpha_step = 1  # Adjust this value to control the speed of the fade
        
        self.current_alpha -= alpha_step
        if self.current_alpha < 0:
            self.current_alpha = 0
        
        # Set the alpha transparency on the border color
        border_color = Color( self.target_color.getRed(), self.target_color.getGreen(), self.target_color.getBlue(), self.current_alpha )

        self.url_pnl.setBorder( LineBorder( border_color, 1 ) )

        if self.current_alpha > 0:
            self.timer.restart()  # Continue the fade effect
        else:
            self.url_pnl.setBorder(None)  # Remove the border completely when alpha becomes 0

#
# Extend DocumentListner saving the state
#
class TextFieldSaveStateListener( DocumentListener ):
    
    def __init__( self, callbacks, text_component, savestate_key ):
        self.text_component = text_component
        self.callbacks = callbacks
        self.savestate_key = savestate_key

    def insertUpdate( self, event ):
        self._text_updated( event )

    def removeUpdate( self, event ):
        self._text_updated( event )

    def _text_updated( self, event ):
        text = self.text_component.getText()
        self.callbacks.saveExtensionSetting( SAVESTATE_PREFIX+self.savestate_key, text )

